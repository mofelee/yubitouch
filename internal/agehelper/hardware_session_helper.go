package agehelper

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/parentwatch"
	"github.com/mofelee/yubitouch/internal/pin"
)

const (
	internalHardwareSessionMode = "hardware-session"
	internalPINResolverMode     = "pin-resolver"
	sessionIDEnvironment        = "YUBITOUCH_INTERNAL_AGE_SESSION_ID"
	requestIDEnvironment        = "YUBITOUCH_INTERNAL_AGE_REQUEST_ID"
	resolverGroupEnvironment    = "YUBITOUCH_INTERNAL_AGE_RESOLVER_GROUP"
	resolverGroupInherited      = "inherited"
	resolverGroupIsolated       = "isolated"
	maxRetainedRequestIDs       = 65536
)

type retainedHardwareSession interface {
	Login(context.Context, []byte) error
	Validate(context.Context) error
	Derive(context.Context, [32]byte) ([32]byte, error)
	Close() error
}

type hardwareSessionHelperDependencies struct {
	loadConfig       configSnapshotLoader
	inspectConfig    func(string) (configSnapshotBinding, error)
	lockConfig       func(string) (func(), error)
	openSession      func(context.Context, config.Config, agehardware.Target) (retainedHardwareSession, error)
	resolvePIN       func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error)
	disableCoreDump  func() error
	verifyParent     func() error
	watchParentDeath func(func(string) string) (func(), error)
	replayLimit      int
}

type productionRetainedSession struct {
	backend *agehardware.Backend
	session *agehardware.Session
}

func (s *productionRetainedSession) Login(ctx context.Context, value []byte) error {
	return s.session.Login(ctx, value)
}

func (s *productionRetainedSession) Validate(ctx context.Context) error {
	return s.session.Validate(ctx)
}

func (s *productionRetainedSession) Derive(ctx context.Context, peer [32]byte) ([32]byte, error) {
	return s.session.Derive(ctx, peer)
}

func (s *productionRetainedSession) Close() error {
	if s == nil {
		return nil
	}
	var result error
	if s.session != nil {
		result = s.session.Close()
		s.session = nil
	}
	if s.backend != nil {
		if err := s.backend.Close(); result == nil {
			result = err
		}
		s.backend = nil
	}
	return result
}

func productionHardwareSessionHelperDependencies() hardwareSessionHelperDependencies {
	executable, _ := os.Executable()
	environment := append([]string(nil), os.Environ()...)
	return hardwareSessionHelperDependencies{
		loadConfig:    loadStableConfigSnapshot,
		inspectConfig: inspectConfigSnapshot,
		lockConfig:    config.AcquireSharedLock,
		openSession: func(ctx context.Context, cfg config.Config, target agehardware.Target) (retainedHardwareSession, error) {
			backend := agehardware.New(cfg.YKCS11Path)
			session, err := backend.OpenSession(ctx, target)
			if err != nil {
				_ = backend.Close()
				return nil, err
			}
			return &productionRetainedSession{backend: backend, session: session}, nil
		},
		resolvePIN: func(ctx context.Context, configPath string, sessionID sessionIdentifier, requestID requestIdentifier, binding configSnapshotBinding) ([]byte, error) {
			return resolvePINWithProcess(ctx, executable, configPath, environment, sessionID, requestID, binding, func(path string) *exec.Cmd {
				return exec.Command(path)
			})
		},
		disableCoreDump:  disableCoreDumps,
		verifyParent:     verifyParentProcess,
		watchParentDeath: startParentLifetimeWatch,
	}
}

func runHardwareSessionInternal(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	getenv func(string) string,
	home string,
	deps hardwareSessionHelperDependencies,
) (bool, int) {
	if getenv == nil || getenv(internalModeEnvironment) != internalHardwareSessionMode {
		return false, 0
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.disableCoreDump == nil || deps.disableCoreDump() != nil ||
		deps.verifyParent == nil || deps.verifyParent() != nil || deps.watchParentDeath == nil {
		return true, helperFailureExitCode
	}
	stopParentWatch, err := deps.watchParentDeath(getenv)
	if err != nil || stopParentWatch == nil {
		return true, helperFailureExitCode
	}
	defer stopParentWatch()

	sessionID, err := parseSessionIdentifier(getenv(sessionIDEnvironment))
	if err != nil {
		return true, helperFailureExitCode
	}
	configPath, ok := internalConfigPath(home, getenv)
	if !ok || deps.loadConfig == nil || deps.inspectConfig == nil || deps.lockConfig == nil ||
		deps.openSession == nil || deps.resolvePIN == nil {
		return true, helperFailureExitCode
	}
	var cfg config.Config
	var hardwarePublic ageprofile.PublicKey
	defer clear(hardwarePublic[:])
	var expected *ageprofile.Recipient
	var target agehardware.Target
	var configBinding configSnapshotBinding
	initialized := false

	reader := bufio.NewReaderSize(stdin, maxSessionRequestFrame+4)
	var session retainedHardwareSession
	replayLimit := deps.replayLimit
	if replayLimit <= 0 || replayLimit > maxRetainedRequestIDs {
		replayLimit = maxRetainedRequestIDs
	}
	// Entries survive into another request only after a successful touch-gated
	// operation. Every failure destroys the process and this bounded set.
	replayGuard := newRequestReplayGuard(replayLimit)
	defer func() {
		if session != nil {
			_ = session.Close()
		}
	}()

	for {
		if _, err := reader.Peek(1); errors.Is(err, io.EOF) {
			return true, 0
		} else if err != nil {
			return true, helperFailureExitCode
		}
		encoded, err := readFrame(reader, maxSessionRequestFrame)
		if err != nil {
			return true, helperFailureExitCode
		}
		requestID, request, err := unmarshalSessionRequest(encoded, sessionID)
		clear(encoded)
		if err != nil {
			return true, helperFailureExitCode
		}
		if class := replayGuard.accept(requestID); class != "" {
			_ = writeSessionEarlyResult(stdout, sessionID, requestID, class)
			return true, helperFailureExitCode
		}
		releaseConfig, lockErr := deps.lockConfig(configPath)
		if lockErr != nil || releaseConfig == nil {
			if releaseConfig != nil {
				releaseConfig()
			}
			_ = writeSessionEarlyResult(stdout, sessionID, requestID, ErrorConfiguration)
			return true, helperFailureExitCode
		}
		if !initialized {
			cfg, configBinding, err = deps.loadConfig(configPath, home)
			if err != nil || cfg.Age == nil {
				releaseConfig()
				_ = writeSessionEarlyResult(stdout, sessionID, requestID, ErrorConfiguration)
				return true, helperFailureExitCode
			}
			var publicOK bool
			hardwarePublic, publicOK = configuredHardwarePublicKey(cfg)
			if !publicOK {
				releaseConfig()
				_ = writeSessionEarlyResult(stdout, sessionID, requestID, ErrorConfiguration)
				return true, helperFailureExitCode
			}
			expected, err = ageprofile.NewRecipient(hardwarePublic, nil)
			if err != nil {
				releaseConfig()
				_ = writeSessionEarlyResult(stdout, sessionID, requestID, ErrorConfiguration)
				return true, helperFailureExitCode
			}
			target = agehardware.Target{
				Serial:    cfg.Age.Serial,
				Slot:      cfg.Age.Slot,
				PublicKey: [32]byte(hardwarePublic),
			}
			initialized = true
		}

		class := validatePersistentHardwareRequest(request, expected)
		if class == "" && deps.verifyParent() != nil {
			class = ErrorHelper
		}
		if class != "" {
			releaseConfig()
			_ = writeSessionEarlyResult(stdout, sessionID, requestID, class)
			return true, helperFailureExitCode
		}
		if session != nil {
			currentBinding, inspectErr := deps.inspectConfig(configPath)
			if inspectErr != nil || currentBinding != configBinding {
				releaseConfig()
				_ = writeSessionEarlyResult(stdout, sessionID, requestID, ErrorConfiguration)
				return true, helperFailureExitCode
			}
		}

		if session == nil {
			session, err = deps.openSession(ctx, cfg, target)
			if err != nil {
				class = persistentHardwareErrorClass(err, false)
			} else {
				var pinValue []byte
				pinValue, err = deps.resolvePIN(ctx, configPath, sessionID, requestID, configBinding)
				if err != nil || len(pinValue) == 0 || len(pinValue) > maxPINLength {
					secureClear(pinValue)
					class = pinResolverErrorClass(ctx, err)
				} else {
					currentBinding, inspectErr := deps.inspectConfig(configPath)
					if inspectErr != nil || currentBinding != configBinding {
						secureClear(pinValue)
						class = ErrorConfiguration
					} else {
						secureLock(pinValue)
						err = session.Login(ctx, pinValue)
						// Login is a consuming API; unlock the already-cleared buffer now.
						secureClear(pinValue)
						if err != nil {
							class = persistentHardwareErrorClass(err, true)
						}
					}
				}
			}
		}
		if class == "" {
			err = session.Validate(ctx)
			if err != nil {
				class = persistentHardwareErrorClass(err, false)
			}
		}
		if class == "" {
			currentBinding, inspectErr := deps.inspectConfig(configPath)
			if inspectErr != nil || currentBinding != configBinding {
				class = ErrorConfiguration
			}
		}
		if class != "" {
			releaseConfig()
			_ = writeSessionEarlyResult(stdout, sessionID, requestID, class)
			return true, helperFailureExitCode
		}

		if err := writeSessionControl(stdout, marshalSessionReady, sessionID, requestID); err != nil {
			releaseConfig()
			return true, helperFailureExitCode
		}
		if deps.verifyParent() != nil {
			releaseConfig()
			_ = writeSessionEarlyResult(stdout, sessionID, requestID, ErrorHelper)
			return true, helperFailureExitCode
		}
		currentBinding, inspectErr := deps.inspectConfig(configPath)
		if inspectErr != nil || currentBinding != configBinding {
			releaseConfig()
			_ = writeSessionEarlyResult(stdout, sessionID, requestID, ErrorConfiguration)
			return true, helperFailureExitCode
		}
		if err := writeSessionControl(stdout, marshalSessionReadyForTouch, sessionID, requestID); err != nil {
			releaseConfig()
			return true, helperFailureExitCode
		}
		releaseConfig()
		continued, err := readFrame(reader, maxSessionResponseFrame)
		if err != nil {
			return true, helperFailureExitCode
		}
		continuationID, continueErr := unmarshalSessionContinue(continued, sessionID, requestID)
		clear(continued)
		if continueErr != nil {
			return true, helperFailureExitCode
		}
		if deps.verifyParent() != nil {
			clear(continuationID[:])
			return true, helperFailureExitCode
		}
		releaseConfig, lockErr = deps.lockConfig(configPath)
		if lockErr != nil || releaseConfig == nil {
			if releaseConfig != nil {
				releaseConfig()
			}
			_ = writeSessionResult(stdout, sessionID, requestID, continuationID, nil, ErrorConfiguration)
			clear(continuationID[:])
			return true, helperFailureExitCode
		}
		currentBinding, inspectErr = deps.inspectConfig(configPath)
		if inspectErr != nil || currentBinding != configBinding {
			_ = writeSessionResult(stdout, sessionID, requestID, continuationID, nil, ErrorConfiguration)
			releaseConfig()
			clear(continuationID[:])
			return true, helperFailureExitCode
		}

		peer := [32]byte(request.Envelope.EphemeralPublicKey)
		sharedSecret, err := session.Derive(ctx, peer)
		clear(peer[:])
		secureLock(sharedSecret[:])
		if err != nil {
			secureClear(sharedSecret[:])
			_ = writeSessionResult(stdout, sessionID, requestID, continuationID, nil, persistentHardwareErrorClass(err, false))
			releaseConfig()
			clear(continuationID[:])
			return true, helperFailureExitCode
		}
		fileKey, unwrapErr := ageprofile.UnwrapWithSharedSecret(request.Envelope, hardwarePublic, sharedSecret[:])
		secureClear(sharedSecret[:])
		if unwrapErr != nil || len(fileKey) != fileKeySize {
			secureClear(fileKey)
			_ = writeSessionResult(stdout, sessionID, requestID, continuationID, nil, ErrorUnwrap)
			releaseConfig()
			clear(continuationID[:])
			return true, helperFailureExitCode
		}
		secureLock(fileKey)
		writeErr := writeSessionResult(stdout, sessionID, requestID, continuationID, fileKey, "")
		secureClear(fileKey)
		releaseConfig()
		clear(continuationID[:])
		if writeErr != nil {
			return true, helperFailureExitCode
		}
	}
}

type requestReplayGuard struct {
	seen  map[requestIdentifier]struct{}
	limit int
}

func newRequestReplayGuard(limit int) *requestReplayGuard {
	if limit <= 0 || limit > maxRetainedRequestIDs {
		limit = maxRetainedRequestIDs
	}
	return &requestReplayGuard{seen: make(map[requestIdentifier]struct{}), limit: limit}
}

func (g *requestReplayGuard) accept(requestID requestIdentifier) ErrorClass {
	if g == nil || !identifierIsValid(requestID[:]) {
		return ErrorInvalidRequest
	}
	if _, duplicate := g.seen[requestID]; duplicate {
		return ErrorInvalidRequest
	}
	if len(g.seen) >= g.limit {
		return ErrorHelper
	}
	g.seen[requestID] = struct{}{}
	return ""
}

func validatePersistentHardwareRequest(request Request, expected *ageprofile.Recipient) ErrorClass {
	if expected == nil || request.Envelope.Path != ageprofile.PathHardware ||
		request.Envelope.ProfileID != expected.ProfileID() || request.Envelope.KeyID != expected.Hardware().ID {
		return ErrorHardwareMismatch
	}
	return ""
}

func persistentHardwareErrorClass(err error, login bool) ErrorClass {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorTimeout
	case errors.Is(err, context.Canceled):
		return ErrorCanceled
	case errors.Is(err, agehardware.ErrTargetMismatch), errors.Is(err, agehardware.ErrNotDetected):
		return ErrorHardwareMismatch
	case login && errors.Is(err, agehardware.ErrPINLoginFailed):
		return ErrorHardwarePIN
	default:
		return ErrorHardware
	}
}

func pinResolverErrorClass(ctx context.Context, err error) ErrorClass {
	if ctx != nil && ctx.Err() != nil {
		return contextClass(ctx.Err())
	}
	class := ErrorClassOf(err)
	switch class {
	case ErrorConfiguration, ErrorPINProvider, ErrorCanceled, ErrorTimeout, ErrorHelper:
		return class
	default:
		return ErrorPINProvider
	}
}

func writeSessionControl(
	writer io.Writer,
	marshal func(sessionIdentifier, requestIdentifier) ([]byte, error),
	sessionID sessionIdentifier,
	requestID requestIdentifier,
) error {
	encoded, err := marshal(sessionID, requestID)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return writeFrame(writer, encoded, maxSessionResponseFrame)
}

func writeSessionEarlyResult(
	writer io.Writer,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	class ErrorClass,
) error {
	encoded, err := marshalSessionEarlyResult(sessionID, requestID, class)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return writeFrame(writer, encoded, maxSessionResponseFrame)
}

func writeSessionResult(
	writer io.Writer,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	continuationID continuationIdentifier,
	fileKey []byte,
	class ErrorClass,
) error {
	encoded, err := marshalSessionResult(sessionID, requestID, continuationID, fileKey, class)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return writeFrame(writer, encoded, maxSessionResponseFrame)
}

type pinResolverDependencies struct {
	loadConfig       configSnapshotLoader
	resolvePIN       func(context.Context, config.Config) ([]byte, error)
	disableCoreDump  func() error
	verifyParent     func() error
	watchParentDeath func(func(string) string) (func(), error)
}

func productionPINResolverDependencies() pinResolverDependencies {
	return pinResolverDependencies{
		loadConfig:      loadStableConfigSnapshot,
		resolvePIN:      pin.Resolve,
		disableCoreDump: disableCoreDumps,
		verifyParent:    verifyParentProcess,
		watchParentDeath: func(getenv func(string) string) (func(), error) {
			if getenv != nil && getenv(resolverGroupEnvironment) == resolverGroupInherited {
				return startResolverParentLifetimeWatch(getenv)
			}
			if getenv != nil && getenv(resolverGroupEnvironment) == resolverGroupIsolated {
				return startParentLifetimeWatch(getenv)
			}
			return nil, errors.New("PIN resolver process group is unavailable")
		},
	}
}

func runPINResolverInternal(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	getenv func(string) string,
	home string,
	deps pinResolverDependencies,
) (bool, int) {
	if getenv == nil || getenv(internalModeEnvironment) != internalPINResolverMode {
		return false, 0
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.disableCoreDump == nil || deps.disableCoreDump() != nil ||
		deps.verifyParent == nil || deps.verifyParent() != nil || deps.watchParentDeath == nil {
		return true, helperFailureExitCode
	}
	stopParentWatch, err := deps.watchParentDeath(getenv)
	if err != nil || stopParentWatch == nil {
		return true, helperFailureExitCode
	}
	defer stopParentWatch()

	sessionID, err := parseSessionIdentifier(getenv(sessionIDEnvironment))
	if err != nil {
		return true, helperFailureExitCode
	}
	requestID, err := parseRequestIdentifier(getenv(requestIDEnvironment))
	if err != nil {
		return true, helperFailureExitCode
	}
	expectedBinding, err := readPINResolverRequestFrame(stdin, sessionID, requestID)
	if err != nil {
		return true, helperFailureExitCode
	}
	configPath, ok := internalConfigPath(home, getenv)
	if !ok || deps.loadConfig == nil || deps.resolvePIN == nil {
		_ = writePINResolverResponseFrame(stdout, sessionID, requestID, expectedBinding, nil, ErrorConfiguration)
		return true, helperFailureExitCode
	}
	cfg, actualBinding, err := deps.loadConfig(configPath, home)
	if err != nil || cfg.Age == nil || actualBinding != expectedBinding {
		_ = writePINResolverResponseFrame(stdout, sessionID, requestID, expectedBinding, nil, ErrorConfiguration)
		return true, helperFailureExitCode
	}
	if deps.verifyParent() != nil {
		_ = writePINResolverResponseFrame(stdout, sessionID, requestID, expectedBinding, nil, ErrorHelper)
		return true, helperFailureExitCode
	}
	pinValue, err := deps.resolvePIN(ctx, cfg)
	if err != nil || len(pinValue) == 0 || len(pinValue) > maxPINLength {
		secureClear(pinValue)
		class := ErrorPINProvider
		if ctx.Err() != nil {
			class = contextClass(ctx.Err())
		}
		_ = writePINResolverResponseFrame(stdout, sessionID, requestID, expectedBinding, nil, class)
		return true, helperFailureExitCode
	}
	secureLock(pinValue)
	writeErr := writePINResolverResponseFrame(stdout, sessionID, requestID, expectedBinding, pinValue, "")
	secureClear(pinValue)
	if writeErr != nil {
		return true, helperFailureExitCode
	}
	return true, 0
}

type resolverCommandFactory func(string) *exec.Cmd

func resolvePINWithProcess(
	ctx context.Context,
	executable string,
	configPath string,
	environment []string,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	binding configSnapshotBinding,
	command resolverCommandFactory,
) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validExecutable(executable) || !validConfigPath(configPath) || command == nil ||
		!identifierIsValid(sessionID[:]) || !identifierIsValid(requestID[:]) || !validConfigSnapshotBinding(binding) {
		return nil, classError(ErrorHelper)
	}
	cmd := command(executable)
	if cmd == nil {
		return nil, classError(ErrorHelper)
	}
	cmd.Env = sanitizedInternalEnvironment(environment, configPath, internalPINResolverMode,
		sessionIDEnvironment+"="+hex.EncodeToString(sessionID[:]),
		requestIDEnvironment+"="+hex.EncodeToString(requestID[:]),
	)
	cmd.Stderr = io.Discard
	inheritedGroup := os.Getpid() > 1 && syscall.Getpgrp() == os.Getpid()
	groupMode := resolverGroupInherited
	if !inheritedGroup {
		groupMode = resolverGroupIsolated
		configureHelperProcess(cmd)
	}
	cmd.Env = append(cmd.Env, resolverGroupEnvironment+"="+groupMode)
	parentWatch, parentAlive, err := parentwatch.Attach(cmd)
	if err != nil {
		return nil, classError(ErrorHelper)
	}
	requestReader, requestWriter, err := os.Pipe()
	if err != nil {
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		return nil, classError(ErrorHelper)
	}
	responseReader, responseWriter, err := os.Pipe()
	if err != nil {
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		return nil, classError(ErrorHelper)
	}
	cmd.Stdin = requestReader
	cmd.Stdout = responseWriter
	if err := cmd.Start(); err != nil {
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = responseReader.Close()
		_ = responseWriter.Close()
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		return nil, classError(ErrorHelper)
	}
	_ = requestReader.Close()
	_ = responseWriter.Close()
	_ = parentWatch.Close()

	watchStop := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = requestWriter.Close()
			_ = responseReader.Close()
			killResolverProcess(cmd, inheritedGroup)
		case <-watchStop:
		}
	}()

	protocolOK := writePINResolverRequestFrame(requestWriter, sessionID, requestID, binding) == nil
	_ = requestWriter.Close()
	var pinValue []byte
	if protocolOK {
		pinValue, err = readPINResolverResponseFrame(responseReader, sessionID, requestID, binding)
		protocolOK = err == nil
	}
	_ = responseReader.Close()
	if !protocolOK {
		killResolverProcess(cmd, inheritedGroup)
	}
	waitErr := cmd.Wait()
	close(watchStop)
	<-watchDone
	_ = parentAlive.Close()
	if ctx.Err() != nil {
		secureClear(pinValue)
		return nil, classError(contextClass(ctx.Err()))
	}
	if !protocolOK {
		secureClear(pinValue)
		if err != nil && ErrorClassOf(err) != ErrorHelper {
			return nil, err
		}
		return nil, classError(ErrorHelper)
	}
	if waitErr != nil {
		secureClear(pinValue)
		return nil, classError(ErrorHelper)
	}
	secureLock(pinValue)
	return pinValue, nil
}

func killResolverProcess(cmd *exec.Cmd, inheritedGroup bool) {
	if !inheritedGroup {
		killHelperProcessGroup(cmd)
		return
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func sanitizedInternalEnvironment(base []string, configPath, mode string, extra ...string) []string {
	allowed := make([]string, 0, len(base)+len(extra)+3)
	seen := make(map[string]bool)
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || seen[name] || !allowedEnvironmentName(name) {
			continue
		}
		seen[name] = true
		allowed = append(allowed, entry)
	}
	allowed = append(allowed,
		internalModeEnvironment+"="+mode,
		"YUBITOUCH_CONFIG="+configPath,
		parentwatch.Environment(parentWatchEnvironment),
	)
	allowed = append(allowed, extra...)
	return allowed
}

func parseSessionIdentifier(value string) (sessionIdentifier, error) {
	var identifier sessionIdentifier
	if err := decodeIdentifier(value, identifier[:]); err != nil {
		return sessionIdentifier{}, err
	}
	return identifier, nil
}

func parseRequestIdentifier(value string) (requestIdentifier, error) {
	var identifier requestIdentifier
	if err := decodeIdentifier(value, identifier[:]); err != nil {
		return requestIdentifier{}, err
	}
	return identifier, nil
}

func decodeIdentifier(value string, destination []byte) error {
	if len(value) != encodedIdentifierSize || strings.ToLower(value) != value {
		return classError(ErrorHelper)
	}
	if _, err := hex.Decode(destination, []byte(value)); err != nil || !identifierIsValid(destination) {
		clear(destination)
		return classError(ErrorHelper)
	}
	return nil
}

func internalConfigPath(home string, getenv func(string) string) (string, bool) {
	value := getenv("YUBITOUCH_CONFIG")
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	path := config.PathFromEnvironment(home, getenv)
	return path, filepath.IsAbs(path)
}
