package ageservice

import (
	"context"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"time"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageipc"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
)

const (
	defaultProbeTimeout  = 3 * time.Second
	defaultProbeInterval = 250 * time.Millisecond
)

type Backend string

const (
	BackendNone     Backend = "none"
	BackendHardware Backend = "hardware"
	BackendRecovery Backend = "recovery"
)

type Result string

const (
	ResultStarted Result = "started"
	ResultSuccess Result = "success"
)

type Event struct {
	At      time.Time
	Backend Backend
	Result  Result
}

type Sink interface {
	HandleAge(Event)
}

type Probe interface {
	Probe(context.Context, agehardware.Target) (agehardware.ProbeResult, error)
}

// Runner is one killable unwrap operation. Hardware runners may use a shared,
// daemon-owned authenticated helper: Start binds one request, WaitReady returns
// only after PIN resolution has exited and the session is ready for touch, and
// Wait permits that request's private-key operation. Recovery runners remain
// one-shot and use Start followed directly by Wait. Implementations must only
// return a file key and predefined IPC error classes.
type Runner interface {
	Start(context.Context, ageprofile.Envelope) ageipc.ErrorClass
	WaitReady() ageipc.ErrorClass
	Wait() ([]byte, ageipc.ErrorClass)
	CancelCurrent()
}

type RunnerFactory func(ageprofile.Path) Runner

type Options struct {
	Config              config.Config
	Probe               Probe
	Coordinator         *signing.Coordinator
	NewRunner           RunnerFactory
	HardwareInvalidator func() error
	Sink                Sink
	ProbeTimeout        time.Duration
	ProbeInterval       time.Duration
	Now                 func() time.Time
}

type Service struct {
	cfg                 config.Config
	probe               Probe
	coordinator         *signing.Coordinator
	newRunner           RunnerFactory
	hardwareInvalidator func() error
	sink                Sink
	probeTimeout        time.Duration
	probeInterval       time.Duration
	now                 func() time.Time
}

func New(options Options) *Service {
	if options.ProbeTimeout <= 0 {
		options.ProbeTimeout = defaultProbeTimeout
	}
	if options.ProbeInterval <= 0 {
		options.ProbeInterval = defaultProbeInterval
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{
		cfg:                 options.Config,
		probe:               options.Probe,
		coordinator:         options.Coordinator,
		newRunner:           options.NewRunner,
		hardwareInvalidator: options.HardwareInvalidator,
		sink:                options.Sink,
		probeTimeout:        options.ProbeTimeout,
		probeInterval:       options.ProbeInterval,
		now:                 options.Now,
	}
}

func (s *Service) Unwrap(ctx context.Context, requester signing.Requester, request ageprofile.UnwrapRequest) ([]byte, ageipc.ErrorClass) {
	if ctx == nil {
		ctx = context.Background()
	}
	target, recoveryKeyID, class := s.validateRequest(request)
	if class != "" {
		s.publish(BackendNone, class)
		return nil, class
	}
	if class := contextClass(ctx); class != "" {
		s.publish(BackendNone, class)
		return nil, class
	}
	if s.probe == nil {
		_ = s.invalidateHardware()
		s.publish(BackendNone, ageipc.ClassProbeUnavailable)
		return nil, ageipc.ClassProbeUnavailable
	}

	state, class := s.probeOnce(ctx, target)
	if class != "" {
		s.publish(BackendNone, class)
		return nil, class
	}
	if state == agehardware.NotDetected {
		if class := waitContext(ctx, s.probeInterval); class != "" {
			s.publish(BackendNone, class)
			return nil, class
		}
		state, class = s.probeOnce(ctx, target)
		if class != "" {
			s.publish(BackendNone, class)
			return nil, class
		}
	}

	switch state {
	case agehardware.Connected:
		return s.unwrapHardware(ctx, requester, request.Hardware)
	case agehardware.NotDetected:
		if recoveryKeyID == nil || request.Recovery == nil {
			s.publish(BackendNone, ageipc.ClassDeviceNotDetected)
			return nil, ageipc.ClassDeviceNotDetected
		}
		if request.Recovery.KeyID != *recoveryKeyID {
			s.publish(BackendNone, ageipc.ClassInvalidRequest)
			return nil, ageipc.ClassInvalidRequest
		}
		return s.unwrapRecovery(ctx, *request.Recovery)
	case agehardware.Mismatch:
		s.publish(BackendNone, ageipc.ClassTargetMismatch)
		return nil, ageipc.ClassTargetMismatch
	default:
		s.publish(BackendNone, ageipc.ClassProbeUnavailable)
		return nil, ageipc.ClassProbeUnavailable
	}
}

func (s *Service) validateRequest(request ageprofile.UnwrapRequest) (agehardware.Target, *ageprofile.ID, ageipc.ErrorClass) {
	if s.cfg.Age == nil || s.cfg.Age.Algorithm != "x25519" {
		return agehardware.Target{}, nil, ageipc.ClassConfiguration
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s.cfg.Age.PublicKey)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != s.cfg.Age.PublicKey {
		clear(decoded)
		return agehardware.Target{}, nil, ageipc.ClassConfiguration
	}
	var hardware ageprofile.PublicKey
	copy(hardware[:], decoded)
	clear(decoded)

	var recoveryKeyID *ageprofile.ID
	if s.cfg.Age.Recovery != nil {
		key, err := ageprofile.ParseNativeRecipient(s.cfg.Age.Recovery.Recipient)
		if err != nil {
			return agehardware.Target{}, nil, ageipc.ClassConfiguration
		}
		configured, err := ageprofile.NewRecipient(hardware, &key)
		if err != nil {
			return agehardware.Target{}, nil, ageipc.ClassConfiguration
		}
		recovery, ok := configured.Recovery()
		if !ok {
			return agehardware.Target{}, nil, ageipc.ClassConfiguration
		}
		id := recovery.ID
		recoveryKeyID = &id
	}
	recipient, err := ageprofile.NewRecipient(hardware, nil)
	if err != nil {
		return agehardware.Target{}, nil, ageipc.ClassConfiguration
	}
	hardwareKey := recipient.Hardware()
	if _, err := request.Hardware.Stanza(); err != nil {
		return agehardware.Target{}, recoveryKeyID, ageipc.ClassInvalidRequest
	}
	if request.ProfileID != recipient.ProfileID() || request.HardwareKeyID != hardwareKey.ID ||
		request.Hardware.Path != ageprofile.PathHardware || request.Hardware.ProfileID != recipient.ProfileID() ||
		request.Hardware.KeyID != hardwareKey.ID {
		return agehardware.Target{}, recoveryKeyID, ageipc.ClassInvalidRequest
	}
	if request.Recovery != nil {
		if _, err := request.Recovery.Stanza(); err != nil {
			return agehardware.Target{}, recoveryKeyID, ageipc.ClassInvalidRequest
		}
		if request.Recovery.Path != ageprofile.PathRecovery ||
			request.Recovery.ProfileID != recipient.ProfileID() || request.Recovery.KeyID == hardwareKey.ID {
			return agehardware.Target{}, recoveryKeyID, ageipc.ClassInvalidRequest
		}
	}

	var targetPublic [32]byte
	copy(targetPublic[:], hardware[:])
	return agehardware.Target{
		Serial:    s.cfg.Age.Serial,
		Slot:      s.cfg.Age.Slot,
		PublicKey: targetPublic,
	}, recoveryKeyID, ""
}

func (s *Service) probeOnce(ctx context.Context, target agehardware.Target) (agehardware.ProbeState, ageipc.ErrorClass) {
	probeCtx, cancel := context.WithTimeout(ctx, s.probeTimeout)
	defer cancel()
	result, err := s.probe.Probe(probeCtx, target)
	probeContextErr := probeCtx.Err()
	// This request does not own the shared hardware manager until it enters the
	// coordinator. Its cancellation must not invalidate another active request.
	if class := contextClass(ctx); class != "" {
		return agehardware.Unavailable, class
	}
	trustedConnected := result.State == agehardware.Connected && err == nil && probeContextErr == nil
	if !trustedConnected {
		if s.invalidateHardware() != nil {
			return agehardware.Unavailable, ageipc.ClassProbeUnavailable
		}
	}
	if probeContextErr != nil {
		return agehardware.Unavailable, ageipc.ClassProbeUnavailable
	}
	switch result.State {
	case agehardware.Connected:
		if err == nil {
			return result.State, ""
		}
	case agehardware.NotDetected:
		if err == nil {
			return result.State, ""
		}
	case agehardware.Mismatch:
		return result.State, ageipc.ClassTargetMismatch
	case agehardware.Unavailable:
		return result.State, ageipc.ClassProbeUnavailable
	}
	if errors.Is(err, agehardware.ErrTargetMismatch) {
		return agehardware.Mismatch, ageipc.ClassTargetMismatch
	}
	return agehardware.Unavailable, ageipc.ClassProbeUnavailable
}

func (s *Service) invalidateHardware() error {
	if s.hardwareInvalidator != nil {
		return s.hardwareInvalidator()
	}
	return nil
}

func (s *Service) unwrapHardware(ctx context.Context, requester signing.Requester, envelope ageprofile.Envelope) ([]byte, ageipc.ErrorClass) {
	if s.coordinator == nil || s.newRunner == nil {
		s.publish(BackendHardware, ageipc.ClassInternal)
		return nil, ageipc.ClassInternal
	}
	runner := s.newRunner(ageprofile.PathHardware)
	if runner == nil {
		s.publish(BackendHardware, ageipc.ClassInternal)
		return nil, ageipc.ClassInternal
	}
	s.publish(BackendHardware, ageipc.ErrorClass(ResultStarted))

	var canceled atomic.Bool
	result := make(chan []byte, 1)
	var helperClass atomic.Value
	initializer := signing.InitializerFunc(func(prepareCtx context.Context) error {
		if class := runner.Start(prepareCtx, envelope); class != "" {
			helperClass.Store(class)
			return classifiedError(class)
		}
		if class := runner.WaitReady(); class != "" {
			helperClass.Store(class)
			return classifiedError(class)
		}
		return nil
	})
	cancelCall := func() {
		canceled.Store(true)
		runner.CancelCurrent()
	}
	err := s.coordinator.RunCancelableFor(
		ctx,
		requester,
		signing.OperationAgeDecrypt,
		initializer,
		func() error {
			fileKey, class := runner.Wait()
			if canceled.Load() {
				clear(fileKey)
				return context.Canceled
			}
			if class != "" {
				helperClass.Store(class)
				clear(fileKey)
				return classifiedError(class)
			}
			if len(fileKey) != 16 {
				clear(fileKey)
				helperClass.Store(ageipc.ClassHardwareFailed)
				return classifiedError(ageipc.ClassHardwareFailed)
			}
			result <- fileKey
			return nil
		},
		cancelCall,
	)
	if err != nil {
		class := coordinatorClass(err)
		if value := helperClass.Load(); value != nil && class == ageipc.ClassHardwareFailed {
			class = value.(ageipc.ErrorClass)
		}
		select {
		case fileKey := <-result:
			clear(fileKey)
		default:
		}
		s.publish(BackendHardware, class)
		return nil, class
	}
	fileKey := <-result
	s.publish(BackendHardware, ageipc.ErrorClass(ResultSuccess))
	return fileKey, ""
}

func (s *Service) unwrapRecovery(ctx context.Context, envelope ageprofile.Envelope) ([]byte, ageipc.ErrorClass) {
	if s.newRunner == nil {
		s.publish(BackendRecovery, ageipc.ClassRecoveryUnavailable)
		return nil, ageipc.ClassRecoveryUnavailable
	}
	runner := s.newRunner(ageprofile.PathRecovery)
	if runner == nil {
		s.publish(BackendRecovery, ageipc.ClassRecoveryUnavailable)
		return nil, ageipc.ClassRecoveryUnavailable
	}
	s.publish(BackendRecovery, ageipc.ErrorClass(ResultStarted))
	class := runner.Start(ctx, envelope)
	var fileKey []byte
	if class == "" {
		fileKey, class = runner.Wait()
	}
	if contextResult := contextClass(ctx); contextResult != "" {
		clear(fileKey)
		class = contextResult
	}
	if class == "" && len(fileKey) != 16 {
		clear(fileKey)
		class = ageipc.ClassRecoveryFailed
	}
	if class != "" {
		clear(fileKey)
		s.publish(BackendRecovery, class)
		return nil, class
	}
	s.publish(BackendRecovery, ageipc.ErrorClass(ResultSuccess))
	return fileKey, ""
}

func coordinatorClass(err error) ageipc.ErrorClass {
	switch {
	case errors.Is(err, signing.ErrCanceled), errors.Is(err, context.Canceled):
		return ageipc.ClassCanceled
	case errors.Is(err, signing.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return ageipc.ClassTimeout
	}
	var classified classifiedError
	if errors.As(err, &classified) {
		return ageipc.ErrorClass(classified)
	}
	return ageipc.ClassHardwareFailed
}

func contextClass(ctx context.Context) ageipc.ErrorClass {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ageipc.ClassTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return ageipc.ClassCanceled
	}
	return ""
}

func waitContext(ctx context.Context, duration time.Duration) ageipc.ErrorClass {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return contextClass(ctx)
	case <-timer.C:
		return ""
	}
}

func (s *Service) publish(backend Backend, result ageipc.ErrorClass) {
	if s.sink == nil {
		return
	}
	s.sink.HandleAge(Event{At: s.now().UTC(), Backend: backend, Result: Result(result)})
}

type classifiedError ageipc.ErrorClass

func (e classifiedError) Error() string { return string(e) }
