package ageservice

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageipc"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
)

func TestConnectedTargetUsesOnlyHardware(t *testing.T) {
	cfg, request := testProfile(t, true)
	hardware := &fakeRunner{key: bytes.Repeat([]byte{0x42}, 16)}
	recovery := &fakeRunner{class: ageipc.ClassInternal}
	service := testService(cfg, &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}}, func(path ageprofile.Path) Runner {
		if path == ageprofile.PathHardware {
			return hardware
		}
		return recovery
	})

	fileKey, class := service.Unwrap(context.Background(), signing.Requester{Name: "test"}, request)
	if class != "" || !bytes.Equal(fileKey, hardware.key) {
		t.Fatalf("Unwrap = %x, %q", fileKey, class)
	}
	if hardware.calls != 1 || recovery.calls != 0 {
		t.Fatalf("helper calls: hardware=%d recovery=%d", hardware.calls, recovery.calls)
	}
}

func TestTwoConfirmedMissingProbesUseRecoveryOnce(t *testing.T) {
	cfg, request := testProfile(t, true)
	hardware := &fakeRunner{class: ageipc.ClassInternal}
	recovery := &fakeRunner{key: bytes.Repeat([]byte{0x24}, 16)}
	probe := &fakeProbe{states: []agehardware.ProbeState{agehardware.NotDetected, agehardware.NotDetected}}
	service := testService(cfg, probe, pathFactory(hardware, recovery))

	fileKey, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	if class != "" || !bytes.Equal(fileKey, recovery.key) {
		t.Fatalf("Unwrap = %x, %q", fileKey, class)
	}
	if probe.calls != 2 || hardware.calls != 0 || recovery.calls != 1 {
		t.Fatalf("calls: probe=%d hardware=%d recovery=%d", probe.calls, hardware.calls, recovery.calls)
	}
}

func TestReinsertOnSecondProbeReturnsToHardware(t *testing.T) {
	cfg, request := testProfile(t, true)
	hardware := &fakeRunner{key: bytes.Repeat([]byte{0x31}, 16)}
	recovery := &fakeRunner{class: ageipc.ClassInternal}
	probe := &fakeProbe{states: []agehardware.ProbeState{agehardware.NotDetected, agehardware.Connected}}
	service := testService(cfg, probe, pathFactory(hardware, recovery))

	_, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	if class != "" || probe.calls != 2 || hardware.calls != 1 || recovery.calls != 0 {
		t.Fatalf("class=%q calls: probe=%d hardware=%d recovery=%d", class, probe.calls, hardware.calls, recovery.calls)
	}
}

func TestFirstMissingProbeInvalidatesRetainedSessionBeforeRetry(t *testing.T) {
	cfg, request := testProfile(t, false)
	invalidations := 0
	probeCalls := 0
	probe := probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
		probeCalls++
		if probeCalls == 1 {
			return agehardware.ProbeResult{State: agehardware.NotDetected}, nil
		}
		if invalidations != 1 {
			t.Fatalf("second probe started after %d invalidations, want 1", invalidations)
		}
		return agehardware.ProbeResult{State: agehardware.Connected}, nil
	})
	hardware := &fakeRunner{key: bytes.Repeat([]byte{0x31}, 16)}
	service := New(Options{
		Config:      cfg,
		Probe:       probe,
		Coordinator: signing.New(nil, nil, time.Second),
		NewRunner:   pathFactory(hardware, &fakeRunner{}),
		HardwareInvalidator: func() error {
			invalidations++
			return nil
		},
		ProbeInterval: time.Millisecond,
	})

	fileKey, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	clear(fileKey)
	if class != "" || probeCalls != 2 || invalidations != 1 || hardware.calls != 1 {
		t.Fatalf(
			"class=%q probes=%d invalidations=%d hardware=%d",
			class,
			probeCalls,
			invalidations,
			hardware.calls,
		)
	}
}

func TestProbeTrustControlsRetainedSessionInvalidation(t *testing.T) {
	tests := []struct {
		name              string
		probe             Probe
		wantState         agehardware.ProbeState
		wantClass         ageipc.ErrorClass
		wantInvalidations int
		invalidateErr     error
	}{
		{
			name: "connected",
			probe: probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
				return agehardware.ProbeResult{State: agehardware.Connected}, nil
			}),
			wantState: agehardware.Connected,
		},
		{
			name: "not detected",
			probe: probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
				return agehardware.ProbeResult{State: agehardware.NotDetected}, nil
			}),
			wantState:         agehardware.NotDetected,
			wantInvalidations: 1,
		},
		{
			name: "mismatch",
			probe: probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
				return agehardware.ProbeResult{State: agehardware.Mismatch}, agehardware.ErrTargetMismatch
			}),
			wantState:         agehardware.Mismatch,
			wantClass:         ageipc.ClassTargetMismatch,
			wantInvalidations: 1,
		},
		{
			name: "unavailable",
			probe: probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
				return agehardware.ProbeResult{State: agehardware.Unavailable}, agehardware.ErrProbeUnavailable
			}),
			wantState:         agehardware.Unavailable,
			wantClass:         ageipc.ClassProbeUnavailable,
			wantInvalidations: 1,
		},
		{
			name: "connected with error",
			probe: probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
				return agehardware.ProbeResult{State: agehardware.Connected}, errors.New("probe failed")
			}),
			wantState:         agehardware.Unavailable,
			wantClass:         ageipc.ClassProbeUnavailable,
			wantInvalidations: 1,
		},
		{
			name: "timeout",
			probe: probeFunc(func(ctx context.Context, _ agehardware.Target) (agehardware.ProbeResult, error) {
				<-ctx.Done()
				return agehardware.ProbeResult{State: agehardware.Unavailable}, ctx.Err()
			}),
			wantState:         agehardware.Unavailable,
			wantClass:         ageipc.ClassProbeUnavailable,
			wantInvalidations: 1,
		},
		{
			name: "cleanup failure",
			probe: probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
				return agehardware.ProbeResult{State: agehardware.NotDetected}, nil
			}),
			wantState:         agehardware.Unavailable,
			wantClass:         ageipc.ClassProbeUnavailable,
			wantInvalidations: 1,
			invalidateErr:     errors.New("helper was not reaped"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalidations := 0
			service := New(Options{
				Probe: test.probe,
				HardwareInvalidator: func() error {
					invalidations++
					return test.invalidateErr
				},
				ProbeTimeout: 5 * time.Millisecond,
			})
			state, class := service.probeOnce(context.Background(), agehardware.Target{})
			if state != test.wantState || class != test.wantClass || invalidations != test.wantInvalidations {
				t.Fatalf(
					"probeOnce = state:%q class:%q invalidations:%d, want %q %q %d",
					state,
					class,
					invalidations,
					test.wantState,
					test.wantClass,
					test.wantInvalidations,
				)
			}
		})
	}
}

func TestCallerContextEndingDuringProbeDoesNotInvalidateHardware(t *testing.T) {
	for _, test := range []struct {
		name       string
		want       ageipc.ErrorClass
		newContext func() (context.Context, context.CancelFunc)
		cancelNow  bool
	}{
		{
			name: "canceled", want: ageipc.ClassCanceled, cancelNow: true,
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
		{
			name: "deadline", want: ageipc.ClassTimeout,
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			invalidations := 0
			service := New(Options{
				Probe: probeFunc(func(ctx context.Context, _ agehardware.Target) (agehardware.ProbeResult, error) {
					close(entered)
					<-ctx.Done()
					return agehardware.ProbeResult{State: agehardware.Unavailable}, ctx.Err()
				}),
				HardwareInvalidator: func() error {
					invalidations++
					return nil
				},
				ProbeTimeout: time.Second,
			})
			ctx, cancel := test.newContext()
			defer cancel()
			if test.cancelNow {
				go func() {
					<-entered
					cancel()
				}()
			}

			state, class := service.probeOnce(ctx, agehardware.Target{})
			if state != agehardware.Unavailable || class != test.want || invalidations != 0 {
				t.Fatalf("probeOnce = state:%q class:%q invalidations:%d, want unavailable %q 0", state, class, invalidations, test.want)
			}
		})
	}
}

func TestCanceledBeforeProbeDoesNotProbeOrInvalidateHardware(t *testing.T) {
	cfg, request := testProfile(t, false)
	for _, test := range []struct {
		name  string
		probe Probe
	}{
		{name: "probe unavailable"},
		{
			name: "probe configured",
			probe: probeFunc(func(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
				t.Fatal("pre-canceled request called Probe")
				return agehardware.ProbeResult{}, nil
			}),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalidations := 0
			service := New(Options{
				Config:      cfg,
				Probe:       test.probe,
				Coordinator: signing.New(nil, nil, time.Second),
				NewRunner:   pathFactory(&fakeRunner{}, &fakeRunner{}),
				HardwareInvalidator: func() error {
					invalidations++
					return nil
				},
			})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			fileKey, class := service.Unwrap(ctx, signing.Requester{}, request)
			clear(fileKey)
			if class != ageipc.ClassCanceled || invalidations != 0 {
				t.Fatalf("Unwrap class=%q invalidations=%d, want canceled and 0", class, invalidations)
			}
		})
	}
}

func TestFailedProbeInvalidationNeverRetriesOrUsesRecovery(t *testing.T) {
	cfg, request := testProfile(t, true)
	probe := &fakeProbe{states: []agehardware.ProbeState{
		agehardware.NotDetected,
		agehardware.Connected,
	}}
	hardware := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	recovery := &fakeRunner{key: bytes.Repeat([]byte{2}, 16)}
	invalidations := 0
	service := New(Options{
		Config:      cfg,
		Probe:       probe,
		Coordinator: signing.New(nil, nil, time.Second),
		NewRunner:   pathFactory(hardware, recovery),
		HardwareInvalidator: func() error {
			invalidations++
			return errors.New("helper was not reaped")
		},
		ProbeInterval: time.Millisecond,
	})

	_, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	if class != ageipc.ClassProbeUnavailable || probe.calls != 1 || invalidations != 1 ||
		hardware.calls != 0 || recovery.calls != 0 {
		t.Fatalf(
			"class=%q probes=%d invalidations=%d hardware=%d recovery=%d",
			class,
			probe.calls,
			invalidations,
			hardware.calls,
			recovery.calls,
		)
	}
}

func TestUnsafeProbeStatesNeverStartRecovery(t *testing.T) {
	for _, test := range []struct {
		name  string
		state agehardware.ProbeState
		err   error
		want  ageipc.ErrorClass
	}{
		{name: "other device or target mismatch", state: agehardware.Mismatch, err: agehardware.ErrTargetMismatch, want: ageipc.ClassTargetMismatch},
		{name: "probe unavailable", state: agehardware.Unavailable, err: agehardware.ErrProbeUnavailable, want: ageipc.ClassProbeUnavailable},
		{name: "inconsistent connected result", state: agehardware.Connected, err: errors.New("failed"), want: ageipc.ClassProbeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, request := testProfile(t, true)
			hardware := &fakeRunner{}
			recovery := &fakeRunner{}
			service := testService(cfg, &fakeProbe{states: []agehardware.ProbeState{test.state}, errors: []error{test.err}}, pathFactory(hardware, recovery))
			_, class := service.Unwrap(context.Background(), signing.Requester{}, request)
			if class != test.want || hardware.calls != 0 || recovery.calls != 0 {
				t.Fatalf("class=%q hardware=%d recovery=%d", class, hardware.calls, recovery.calls)
			}
		})
	}
}

func TestHardwareFailureNeverFallsBack(t *testing.T) {
	cfg, request := testProfile(t, true)
	hardware := &fakeRunner{readyClass: ageipc.ClassPINFailed}
	recovery := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	lifecycle := &signingEventRecorder{}
	service := New(Options{
		Config:        cfg,
		Probe:         &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}},
		Coordinator:   signing.New(nil, lifecycle, time.Second),
		NewRunner:     pathFactory(hardware, recovery),
		ProbeInterval: time.Millisecond,
	})

	_, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	if class != ageipc.ClassPINFailed || hardware.calls != 1 || hardware.waitCalls != 0 || recovery.calls != 0 {
		t.Fatalf("class=%q hardware=%d waits=%d recovery=%d", class, hardware.calls, hardware.waitCalls, recovery.calls)
	}
	want := []signing.EventType{signing.EventInitializing, signing.EventFailure}
	if got := lifecycle.types(); !signingEventTypesEqual(got, want) {
		t.Fatalf("lifecycle = %v, want %v", got, want)
	}
}

func TestHardwareTouchWaitBeginsOnlyAfterPINPreparation(t *testing.T) {
	cfg, request := testProfile(t, false)
	readyEntered := make(chan struct{})
	readyGate := make(chan struct{})
	hardware := &fakeRunner{
		key:          bytes.Repeat([]byte{0x42}, 16),
		readyEntered: readyEntered,
		readyGate:    readyGate,
	}
	lifecycle := &signingEventRecorder{}
	service := New(Options{
		Config:        cfg,
		Probe:         &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}},
		Coordinator:   signing.New(nil, lifecycle, time.Second),
		NewRunner:     pathFactory(hardware, &fakeRunner{}),
		ProbeInterval: time.Millisecond,
	})

	type unwrapResult struct {
		key   []byte
		class ageipc.ErrorClass
	}
	result := make(chan unwrapResult, 1)
	go func() {
		key, class := service.Unwrap(context.Background(), signing.Requester{}, request)
		result <- unwrapResult{key: key, class: class}
	}()
	<-readyEntered
	if got := lifecycle.types(); !signingEventTypesEqual(got, []signing.EventType{signing.EventInitializing}) {
		t.Fatalf("lifecycle while PIN provider is blocked = %v", got)
	}
	if hardware.waitCalls != 0 {
		t.Fatalf("private operation started before PIN preparation: waits=%d", hardware.waitCalls)
	}

	close(readyGate)
	got := <-result
	defer clear(got.key)
	if got.class != "" || !bytes.Equal(got.key, hardware.key) {
		t.Fatalf("Unwrap = %x, %q", got.key, got.class)
	}
	want := []signing.EventType{signing.EventInitializing, signing.EventWaiting, signing.EventSuccess}
	if events := lifecycle.types(); !signingEventTypesEqual(events, want) {
		t.Fatalf("lifecycle = %v, want %v", events, want)
	}
}

func TestCancelAfterHardwareReadyDoesNotContinueAndReleasesPIVQueue(t *testing.T) {
	cfg, request := testProfile(t, true)
	hardware := &fakeRunner{}
	recovery := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	waitingEntered := make(chan struct{})
	releaseWaiting := make(chan struct{})
	lifecycle := &blockingSigningSink{
		signingEventRecorder: signingEventRecorder{},
		waitingEntered:       waitingEntered,
		releaseWaiting:       releaseWaiting,
	}
	coordinator := signing.New(nil, lifecycle, time.Second)
	service := New(Options{
		Config:        cfg,
		Probe:         &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}},
		Coordinator:   coordinator,
		NewRunner:     pathFactory(hardware, recovery),
		ProbeInterval: time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan ageipc.ErrorClass, 1)
	go func() {
		_, class := service.Unwrap(ctx, signing.Requester{}, request)
		result <- class
	}()
	<-waitingEntered
	hardware.mu.Lock()
	canceled := hardware.canceled
	hardware.mu.Unlock()
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("ready helper was not canceled")
	}
	close(releaseWaiting)
	if class := <-result; class != ageipc.ClassCanceled {
		t.Fatalf("class = %q, want %q", class, ageipc.ClassCanceled)
	}
	hardware.mu.Lock()
	waitCalls, cancels := hardware.waitCalls, hardware.cancels
	hardware.mu.Unlock()
	recovery.mu.Lock()
	recoveryCalls := recovery.calls
	recovery.mu.Unlock()
	if waitCalls != 0 || cancels != 1 || recoveryCalls != 0 {
		t.Fatalf("waits=%d cancels=%d recovery=%d", waitCalls, cancels, recoveryCalls)
	}
	want := []signing.EventType{signing.EventInitializing, signing.EventWaiting, signing.EventCanceled}
	if got := lifecycle.types(); !signingEventTypesEqual(got, want) {
		t.Fatalf("lifecycle = %v, want %v", got, want)
	}

	nextStarted := make(chan struct{})
	if err := coordinator.RunCancelableFor(
		context.Background(),
		signing.Requester{},
		signing.OperationSSHSign,
		nil,
		func() error {
			close(nextStarted)
			return nil
		},
		nil,
	); err != nil {
		t.Fatalf("next PIV request failed: %v", err)
	}
	select {
	case <-nextStarted:
	default:
		t.Fatal("next PIV request did not start")
	}
}

func TestCancelRacingSuccessfulHardwareResultDiscardsResult(t *testing.T) {
	cfg, request := testProfile(t, true)
	waitEntered := make(chan struct{})
	waitGate := make(chan struct{})
	hardware := &fakeRunner{
		key:         bytes.Repeat([]byte{0x42}, 16),
		waitEntered: waitEntered,
		waitGate:    waitGate,
	}
	recovery := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	coordinator := signing.New(nil, nil, time.Second)
	service := New(Options{
		Config:        cfg,
		Probe:         &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}},
		Coordinator:   coordinator,
		NewRunner:     pathFactory(hardware, recovery),
		ProbeInterval: time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan ageipc.ErrorClass, 1)
	go func() {
		fileKey, class := service.Unwrap(ctx, signing.Requester{}, request)
		clear(fileKey)
		result <- class
	}()
	<-waitEntered
	cancel()
	hardware.mu.Lock()
	canceled := hardware.canceled
	hardware.mu.Unlock()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("successful-result race did not cancel the hardware runner")
	}
	close(waitGate)
	if class := <-result; class != ageipc.ClassCanceled {
		t.Fatalf("class = %q, want %q", class, ageipc.ClassCanceled)
	}
	if err := coordinator.RunCancelableFor(
		context.Background(), signing.Requester{}, signing.OperationSSHSign, nil, func() error { return nil }, nil,
	); err != nil {
		t.Fatalf("next PIV request failed: %v", err)
	}
	hardware.mu.Lock()
	waits, cancels := hardware.waitCalls, hardware.cancels
	hardware.mu.Unlock()
	recovery.mu.Lock()
	recoveryCalls := recovery.calls
	recovery.mu.Unlock()
	if waits != 1 || cancels != 1 || recoveryCalls != 0 {
		t.Fatalf("waits=%d cancels=%d recovery=%d", waits, cancels, recoveryCalls)
	}
}

func TestConnectedHardwareAcceptsHistoricalRecoveryLayouts(t *testing.T) {
	withoutRecoveryConfig, withoutRecoveryRequest := testProfile(t, false)
	withRecoveryConfig, withRecoveryRequest := testProfile(t, true)
	_, changedRecoveryRequest := testProfileWithMarkers(t, true, 1, 3)

	tests := []struct {
		name    string
		cfg     config.Config
		request ageprofile.UnwrapRequest
	}{
		{name: "recovery enabled after encryption", cfg: withRecoveryConfig, request: withoutRecoveryRequest},
		{name: "recovery disabled after encryption", cfg: withoutRecoveryConfig, request: withRecoveryRequest},
		{name: "recovery key changed after encryption", cfg: withRecoveryConfig, request: changedRecoveryRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hardware := &fakeRunner{key: bytes.Repeat([]byte{0x42}, 16)}
			recovery := &fakeRunner{class: ageipc.ClassInternal}
			service := testService(test.cfg, &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}}, pathFactory(hardware, recovery))
			fileKey, class := service.Unwrap(context.Background(), signing.Requester{}, test.request)
			if class != "" || !bytes.Equal(fileKey, hardware.key) || hardware.calls != 1 || recovery.calls != 0 {
				t.Fatalf("class=%q hardware=%d recovery=%d", class, hardware.calls, recovery.calls)
			}
		})
	}
}

func TestMissingHardwareRejectsStaleRecoveryBeforeHelper(t *testing.T) {
	cfg, _ := testProfile(t, true)
	_, staleRequest := testProfileWithMarkers(t, true, 1, 3)
	recovery := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	probe := &fakeProbe{states: []agehardware.ProbeState{agehardware.NotDetected, agehardware.NotDetected}}
	service := testService(cfg, probe, pathFactory(&fakeRunner{}, recovery))

	_, class := service.Unwrap(context.Background(), signing.Requester{}, staleRequest)
	if class != ageipc.ClassInvalidRequest || probe.calls != 2 || recovery.calls != 0 {
		t.Fatalf("class=%q probe=%d recovery=%d", class, probe.calls, recovery.calls)
	}
}

func TestMissingWithoutConfiguredRecoveryFailsClosed(t *testing.T) {
	cfg, request := testProfile(t, false)
	recovery := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	service := testService(cfg, &fakeProbe{states: []agehardware.ProbeState{agehardware.NotDetected, agehardware.NotDetected}}, pathFactory(&fakeRunner{}, recovery))

	_, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	if class != ageipc.ClassDeviceNotDetected || recovery.calls != 0 {
		t.Fatalf("class=%q recovery=%d", class, recovery.calls)
	}
}

func TestRequestBindingIsCheckedBeforeProbe(t *testing.T) {
	cfg, request := testProfile(t, true)
	request.Hardware.KeyID[0] ^= 0xff
	probe := &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}}
	invalidations := 0
	service := New(Options{
		Config:      cfg,
		Probe:       probe,
		Coordinator: signing.New(nil, nil, time.Second),
		NewRunner:   pathFactory(&fakeRunner{}, &fakeRunner{}),
		HardwareInvalidator: func() error {
			invalidations++
			return nil
		},
		ProbeInterval: time.Millisecond,
	})

	_, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	if class != ageipc.ClassInvalidRequest || probe.calls != 0 || invalidations != 0 {
		t.Fatalf("class=%q probe calls=%d invalidations=%d", class, probe.calls, invalidations)
	}
}

func TestQueuedCancellationDoesNotStartHardwareHelper(t *testing.T) {
	cfg, request := testProfile(t, false)
	lifecycle := &signingEventRecorder{}
	coordinator := signing.New(nil, lifecycle, time.Second)
	blocking := make(chan struct{})
	started := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- coordinator.RunCancelableFor(context.Background(), signing.Requester{}, signing.OperationSSHSign, nil, func() error {
			close(started)
			<-blocking
			return nil
		}, nil)
	}()
	<-started
	eventsBeforeQueuedRequest := lifecycle.types()
	hardware := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	invalidations := 0
	service := New(Options{
		Config:      cfg,
		Probe:       &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}},
		Coordinator: coordinator,
		NewRunner:   pathFactory(hardware, &fakeRunner{}),
		HardwareInvalidator: func() error {
			invalidations++
			return nil
		},
		ProbeInterval: time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan ageipc.ErrorClass, 1)
	go func() {
		_, class := service.Unwrap(ctx, signing.Requester{}, request)
		result <- class
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if class := <-result; class != ageipc.ClassCanceled {
		t.Fatalf("class = %q", class)
	}
	if hardware.calls != 0 || hardware.readyCalls != 0 || hardware.waitCalls != 0 || hardware.cancels != 0 {
		t.Fatalf(
			"queued helper lifecycle = starts:%d ready:%d waits:%d cancels:%d",
			hardware.calls,
			hardware.readyCalls,
			hardware.waitCalls,
			hardware.cancels,
		)
	}
	if invalidations != 0 {
		t.Fatalf("queued cancellation invalidated %d retained sessions", invalidations)
	}
	if events := lifecycle.types(); !signingEventTypesEqual(events, eventsBeforeQueuedRequest) {
		t.Fatalf("queued cancellation published UI lifecycle: before=%v after=%v", eventsBeforeQueuedRequest, events)
	}
	close(blocking)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestProbeCancellationDoesNotInvalidateAnotherActiveHardwareRequest(t *testing.T) {
	cfg, request := testProfile(t, false)
	readyEntered := make(chan struct{})
	readyGate := make(chan struct{})
	hardware := &fakeRunner{
		key:          bytes.Repeat([]byte{0x42}, 16),
		readyEntered: readyEntered,
		readyGate:    readyGate,
	}
	probeEntered := make(chan struct{})
	var probeMu sync.Mutex
	probeCalls := 0
	probe := probeFunc(func(ctx context.Context, _ agehardware.Target) (agehardware.ProbeResult, error) {
		probeMu.Lock()
		probeCalls++
		call := probeCalls
		probeMu.Unlock()
		if call == 1 {
			return agehardware.ProbeResult{State: agehardware.Connected}, nil
		}
		if call == 2 {
			close(probeEntered)
			<-ctx.Done()
			return agehardware.ProbeResult{State: agehardware.Unavailable}, ctx.Err()
		}
		return agehardware.ProbeResult{State: agehardware.Unavailable}, agehardware.ErrProbeUnavailable
	})
	var invalidationMu sync.Mutex
	invalidations := 0
	service := New(Options{
		Config:      cfg,
		Probe:       probe,
		Coordinator: signing.New(nil, nil, 5*time.Second),
		NewRunner:   pathFactory(hardware, &fakeRunner{}),
		HardwareInvalidator: func() error {
			invalidationMu.Lock()
			invalidations++
			invalidationMu.Unlock()
			hardware.CancelCurrent()
			return nil
		},
		ProbeTimeout:  time.Second,
		ProbeInterval: time.Millisecond,
	})
	type unwrapResult struct {
		key   []byte
		class ageipc.ErrorClass
	}
	activeResult := make(chan unwrapResult, 1)
	go func() {
		key, class := service.Unwrap(context.Background(), signing.Requester{}, request)
		activeResult <- unwrapResult{key: key, class: class}
	}()
	<-readyEntered

	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	queuedResult := make(chan ageipc.ErrorClass, 1)
	go func() {
		key, class := service.Unwrap(queuedCtx, signing.Requester{}, request)
		clear(key)
		queuedResult <- class
	}()
	<-probeEntered
	cancelQueued()
	if class := <-queuedResult; class != ageipc.ClassCanceled {
		t.Fatalf("queued class = %q, want %q", class, ageipc.ClassCanceled)
	}
	close(readyGate)
	active := <-activeResult
	defer clear(active.key)

	invalidationMu.Lock()
	gotInvalidations := invalidations
	invalidationMu.Unlock()
	hardware.mu.Lock()
	starts, waits, cancels := hardware.calls, hardware.waitCalls, hardware.cancels
	hardware.mu.Unlock()
	if active.class != "" || !bytes.Equal(active.key, hardware.key) {
		t.Fatalf("active Unwrap = %x, %q", active.key, active.class)
	}
	if gotInvalidations != 0 || starts != 1 || waits != 1 || cancels != 0 {
		t.Fatalf("active lifecycle = invalidations:%d starts:%d waits:%d cancels:%d", gotInvalidations, starts, waits, cancels)
	}
}

func TestRecoveryCreatesFreshRunnerForEveryRequest(t *testing.T) {
	cfg, request := testProfile(t, true)
	probe := &fakeProbe{states: []agehardware.ProbeState{
		agehardware.NotDetected,
		agehardware.NotDetected,
		agehardware.NotDetected,
		agehardware.NotDetected,
	}}
	var runners []*fakeRunner
	service := testService(cfg, probe, func(path ageprofile.Path) Runner {
		if path != ageprofile.PathRecovery {
			t.Fatalf("runner path = %q, want recovery", path)
		}
		runner := &fakeRunner{key: bytes.Repeat([]byte{0x24}, 16)}
		runners = append(runners, runner)
		return runner
	})

	for range 2 {
		fileKey, class := service.Unwrap(context.Background(), signing.Requester{}, request)
		clear(fileKey)
		if class != "" {
			t.Fatalf("Unwrap class = %q", class)
		}
	}
	if len(runners) != 2 || runners[0] == runners[1] || runners[0].calls != 1 || runners[1].calls != 1 {
		t.Fatalf("recovery runners = %#v, want two distinct one-shot runners", runners)
	}
}

func TestHardwareTimeoutCancelsHelperAndDoesNotRecover(t *testing.T) {
	cfg, request := testProfile(t, true)
	hardware := &fakeRunner{blockReadyUntilCancel: true}
	recovery := &fakeRunner{key: bytes.Repeat([]byte{1}, 16)}
	lifecycle := &signingEventRecorder{}
	service := New(Options{
		Config:        cfg,
		Probe:         &fakeProbe{states: []agehardware.ProbeState{agehardware.Connected}},
		Coordinator:   signing.New(nil, lifecycle, 20*time.Millisecond),
		NewRunner:     pathFactory(hardware, recovery),
		ProbeInterval: time.Millisecond,
	})

	_, class := service.Unwrap(context.Background(), signing.Requester{}, request)
	if class != ageipc.ClassTimeout || hardware.cancels != 1 || recovery.calls != 0 {
		t.Fatalf("class=%q cancels=%d recovery=%d", class, hardware.cancels, recovery.calls)
	}
	want := []signing.EventType{signing.EventInitializing, signing.EventTimeout}
	if got := lifecycle.types(); !signingEventTypesEqual(got, want) {
		t.Fatalf("lifecycle = %v, want %v", got, want)
	}
}

func TestServicePublishesOnlyPredefinedBackendAndResult(t *testing.T) {
	cfg, request := testProfile(t, true)
	sink := &recordingSink{}
	service := New(Options{
		Config:        cfg,
		Probe:         &fakeProbe{states: []agehardware.ProbeState{agehardware.Mismatch}, errors: []error{errors.New("op://private/item and serial 123456")}},
		Coordinator:   signing.New(nil, nil, time.Second),
		NewRunner:     pathFactory(&fakeRunner{}, &fakeRunner{}),
		Sink:          sink,
		ProbeInterval: time.Millisecond,
	})
	_, _ = service.Unwrap(context.Background(), signing.Requester{Name: "secret requester"}, request)
	if len(sink.events) != 1 || sink.events[0].Backend != BackendNone || sink.events[0].Result != Result(ageipc.ClassTargetMismatch) {
		t.Fatalf("events = %+v", sink.events)
	}
}

func testService(cfg config.Config, probe Probe, factory RunnerFactory) *Service {
	return New(Options{
		Config:        cfg,
		Probe:         probe,
		Coordinator:   signing.New(nil, nil, time.Second),
		NewRunner:     factory,
		ProbeInterval: time.Millisecond,
	})
}

func testProfile(t *testing.T, recoveryEnabled bool) (config.Config, ageprofile.UnwrapRequest) {
	return testProfileWithMarkers(t, recoveryEnabled, 1, 2)
}

func testProfileWithMarkers(t *testing.T, recoveryEnabled bool, hardwareMarker, recoveryMarker byte) (config.Config, ageprofile.UnwrapRequest) {
	t.Helper()
	hardware := testPublicKey(t, hardwareMarker)
	var recovery *ageprofile.PublicKey
	if recoveryEnabled {
		key := testPublicKey(t, recoveryMarker)
		recovery = &key
	}
	recipient, err := ageprofile.NewRecipient(hardware, recovery)
	if err != nil {
		t.Fatal(err)
	}
	stanzas, err := recipient.Wrap(bytes.Repeat([]byte{0x7a}, 16))
	if err != nil {
		t.Fatal(err)
	}
	hardwareEnvelope, err := ageprofile.ParseEnvelope(stanzas[0])
	if err != nil {
		t.Fatal(err)
	}
	request := ageprofile.UnwrapRequest{
		ProfileID:     recipient.ProfileID(),
		HardwareKeyID: recipient.Hardware().ID,
		Hardware:      hardwareEnvelope,
	}
	if recoveryEnabled {
		recoveryEnvelope, err := ageprofile.ParseEnvelope(stanzas[1])
		if err != nil {
			t.Fatal(err)
		}
		request.Recovery = &recoveryEnvelope
	}
	cfg := config.Config{Age: &config.AgeConfig{
		Serial:    "123456",
		Slot:      "82",
		Algorithm: "x25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(hardware[:]),
	}}
	if recoveryEnabled {
		cfg.OnePasswordAccount = "configured"
		cfg.Age.Recovery = &config.AgeRecovery{
			Provider:    "1password",
			IdentityRef: "op://configured/reference/field",
			Recipient:   ageprofile.EncodeNativeRecipient(*recovery),
		}
	}
	return cfg, request
}

func testPublicKey(t *testing.T, marker byte) ageprofile.PublicKey {
	t.Helper()
	scalar := bytes.Repeat([]byte{marker}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(scalar)
	clear(scalar)
	if err != nil {
		t.Fatal(err)
	}
	var publicKey ageprofile.PublicKey
	copy(publicKey[:], privateKey.PublicKey().Bytes())
	return publicKey
}

type fakeProbe struct {
	mu     sync.Mutex
	states []agehardware.ProbeState
	errors []error
	calls  int
}

type probeFunc func(context.Context, agehardware.Target) (agehardware.ProbeResult, error)

func (f probeFunc) Probe(ctx context.Context, target agehardware.Target) (agehardware.ProbeResult, error) {
	return f(ctx, target)
}

func (p *fakeProbe) Probe(context.Context, agehardware.Target) (agehardware.ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	index := p.calls
	p.calls++
	if index >= len(p.states) {
		return agehardware.ProbeResult{State: agehardware.Unavailable}, agehardware.ErrProbeUnavailable
	}
	var err error
	if index < len(p.errors) {
		err = p.errors[index]
	}
	return agehardware.ProbeResult{State: p.states[index]}, err
}

type fakeRunner struct {
	mu                    sync.Mutex
	key                   []byte
	startClass            ageipc.ErrorClass
	readyClass            ageipc.ErrorClass
	class                 ageipc.ErrorClass
	calls                 int
	readyCalls            int
	waitCalls             int
	cancels               int
	blockReadyUntilCancel bool
	blockUntilCancel      bool
	readyEntered          chan struct{}
	readyGate             <-chan struct{}
	waitEntered           chan struct{}
	waitGate              <-chan struct{}
	canceled              chan struct{}
	ctx                   context.Context
}

func (r *fakeRunner) Start(ctx context.Context, _ ageprofile.Envelope) ageipc.ErrorClass {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.canceled == nil {
		r.canceled = make(chan struct{})
	}
	r.ctx = ctx
	return r.startClass
}

func (r *fakeRunner) WaitReady() ageipc.ErrorClass {
	r.mu.Lock()
	r.readyCalls++
	if r.canceled == nil {
		r.canceled = make(chan struct{})
	}
	canceled := r.canceled
	ctx := r.ctx
	block := r.blockReadyUntilCancel
	entered := r.readyEntered
	gate := r.readyGate
	class := r.readyClass
	r.mu.Unlock()
	if entered != nil {
		select {
		case <-entered:
		default:
			close(entered)
		}
	}
	if gate != nil {
		select {
		case <-ctx.Done():
			return ageipc.ClassCanceled
		case <-canceled:
			return ageipc.ClassCanceled
		case <-gate:
		}
	}
	if block {
		select {
		case <-ctx.Done():
			return ageipc.ClassCanceled
		case <-canceled:
			return ageipc.ClassCanceled
		}
	}
	return class
}

func (r *fakeRunner) Wait() ([]byte, ageipc.ErrorClass) {
	r.mu.Lock()
	r.waitCalls++
	if r.canceled == nil {
		r.canceled = make(chan struct{})
	}
	canceled := r.canceled
	ctx := r.ctx
	block := r.blockUntilCancel
	entered := r.waitEntered
	gate := r.waitGate
	key := append([]byte(nil), r.key...)
	class := r.class
	r.mu.Unlock()
	if entered != nil {
		select {
		case <-entered:
		default:
			close(entered)
		}
	}
	if gate != nil {
		<-gate
	}
	if block {
		select {
		case <-ctx.Done():
			return nil, ageipc.ClassCanceled
		case <-canceled:
			return nil, ageipc.ClassCanceled
		}
	}
	return key, class
}

func (r *fakeRunner) CancelCurrent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancels++
	if r.canceled == nil {
		r.canceled = make(chan struct{})
	}
	select {
	case <-r.canceled:
	default:
		close(r.canceled)
	}
}

func pathFactory(hardware, recovery Runner) RunnerFactory {
	return func(path ageprofile.Path) Runner {
		if path == ageprofile.PathHardware {
			return hardware
		}
		return recovery
	}
}

type recordingSink struct {
	events []Event
}

func (s *recordingSink) HandleAge(event Event) {
	s.events = append(s.events, event)
}

type signingEventRecorder struct {
	mu     sync.Mutex
	events []signing.EventType
}

type blockingSigningSink struct {
	signingEventRecorder
	waitingEntered chan struct{}
	releaseWaiting <-chan struct{}
	waitingOnce    sync.Once
}

func (s *blockingSigningSink) Handle(event signing.Event) {
	if event.Type == signing.EventWaiting {
		s.waitingOnce.Do(func() {
			close(s.waitingEntered)
			<-s.releaseWaiting
		})
	}
	s.signingEventRecorder.Handle(event)
}

func (r *signingEventRecorder) Handle(event signing.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event.Type)
}

func (r *signingEventRecorder) types() []signing.EventType {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]signing.EventType(nil), r.events...)
}

func signingEventTypesEqual(got, want []signing.EventType) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
