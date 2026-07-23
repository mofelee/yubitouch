package agehelper

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
)

type fakeRetainedSession struct {
	private *ecdh.PrivateKey

	loginCalls    int
	validateCalls int
	deriveCalls   int
	closeCalls    int
	loginErr      error
	validateErr   error
	deriveErr     error
	resolverDone  *bool
	loginCheck    func() error
	validateCheck func() error
	deriveCheck   func() error
}

func (s *fakeRetainedSession) Login(_ context.Context, value []byte) error {
	s.loginCalls++
	if s.resolverDone != nil && !*s.resolverDone {
		return errors.New("login ran before resolver completed")
	}
	if string(value) != "123456" {
		return errors.New("login received the wrong PIN")
	}
	var checkErr error
	if s.loginCheck != nil {
		checkErr = s.loginCheck()
	}
	clear(value)
	if checkErr != nil {
		return checkErr
	}
	return s.loginErr
}

func (s *fakeRetainedSession) Validate(context.Context) error {
	s.validateCalls++
	if s.validateCheck != nil {
		if err := s.validateCheck(); err != nil {
			return err
		}
	}
	return s.validateErr
}

func (s *fakeRetainedSession) Derive(_ context.Context, peer [32]byte) ([32]byte, error) {
	s.deriveCalls++
	if s.deriveCheck != nil {
		if err := s.deriveCheck(); err != nil {
			return [32]byte{}, err
		}
	}
	if s.deriveErr != nil {
		return [32]byte{}, s.deriveErr
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return [32]byte{}, err
	}
	shared, err := s.private.ECDH(peerKey)
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(shared)
	var result [32]byte
	copy(result[:], shared)
	return result, nil
}

func (s *fakeRetainedSession) Close() error {
	s.closeCalls++
	return nil
}

type persistentHelperHarness struct {
	requestWriter  *io.PipeWriter
	responseReader *io.PipeReader
	result         chan helperRunResult
	configPath     string
}

type helperRunResult struct {
	handled bool
	code    int
}

func startPersistentHelperHarness(
	t *testing.T,
	fixture helperFixture,
	deps hardwareSessionHelperDependencies,
) (*persistentHelperHarness, sessionIdentifier) {
	t.Helper()
	sessionID, err := newSessionIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte("test configuration snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	helperReader, requestWriter := io.Pipe()
	responseReader, helperWriter := io.Pipe()
	result := make(chan helperRunResult, 1)
	getenv := func(name string) string {
		switch name {
		case internalModeEnvironment:
			return internalHardwareSessionMode
		case sessionIDEnvironment:
			return hex.EncodeToString(sessionID[:])
		case "YUBITOUCH_CONFIG":
			return configPath
		default:
			return ""
		}
	}
	go func() {
		handled, code := runHardwareSessionInternal(context.Background(), helperReader, helperWriter, getenv, "/home/test", deps)
		_ = helperReader.Close()
		_ = helperWriter.Close()
		result <- helperRunResult{handled: handled, code: code}
	}()
	return &persistentHelperHarness{
		requestWriter: requestWriter, responseReader: responseReader, result: result, configPath: configPath,
	}, sessionID
}

func successfulPersistentHelperDependencies(fixture helperFixture, session retainedHardwareSession) hardwareSessionHelperDependencies {
	return hardwareSessionHelperDependencies{
		loadConfig: func(string, string) (config.Config, configSnapshotBinding, error) {
			return fixture.cfg, fixedConfigSnapshotBinding(), nil
		},
		inspectConfig: func(string) (configSnapshotBinding, error) { return fixedConfigSnapshotBinding(), nil },
		lockConfig: func(string) (func(), error) {
			return func() {}, nil
		},
		openSession: func(context.Context, config.Config, agehardware.Target) (retainedHardwareSession, error) {
			return session, nil
		},
		resolvePIN: func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error) {
			return []byte("123456"), nil
		},
		disableCoreDump: func() error { return nil },
		verifyParent:    func() error { return nil },
		watchParentDeath: func(func(string) string) (func(), error) {
			return func() {}, nil
		},
	}
}

func TestPersistentHardwareHelperReusesOneLoginForTwoDerives(t *testing.T) {
	fixture := newHelperFixture(t)
	resolverDone := false
	session := &fakeRetainedSession{private: fixture.hardwarePrivate, resolverDone: &resolverDone}
	deps := successfulPersistentHelperDependencies(fixture, session)
	openCalls := 0
	resolverCalls := 0
	deps.openSession = func(_ context.Context, _ config.Config, target agehardware.Target) (retainedHardwareSession, error) {
		openCalls++
		if target.Serial != fixture.cfg.Age.Serial || target.Slot != fixture.cfg.Age.Slot {
			t.Fatal("persistent helper changed the hardware target")
		}
		return session, nil
	}
	deps.resolvePIN = func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error) {
		resolverCalls++
		resolverDone = true
		return []byte("123456"), nil
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)

	for requestNumber := 0; requestNumber < 2; requestNumber++ {
		requestID, err := newRequestIdentifier()
		if err != nil {
			t.Fatal(err)
		}
		writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
		readPersistentTestReady(t, harness.responseReader, sessionID, requestID)
		continuationID := writePersistentTestContinue(t, harness.requestWriter, sessionID, requestID)
		fileKey := readPersistentTestResult(t, harness.responseReader, sessionID, requestID, continuationID)
		if !bytes.Equal(fileKey, fixture.fileKey) {
			t.Fatal("persistent helper returned the wrong file key")
		}
		ClearSecret(fileKey)
	}
	_ = harness.requestWriter.Close()
	result := <-harness.result
	_ = harness.responseReader.Close()
	if !result.handled || result.code != 0 {
		t.Fatalf("helper result = %+v", result)
	}
	if openCalls != 1 || resolverCalls != 1 || session.loginCalls != 1 ||
		session.validateCalls != 2 || session.deriveCalls != 2 || session.closeCalls != 1 {
		t.Fatalf("open=%d resolver=%d login=%d validate=%d derive=%d close=%d",
			openCalls, resolverCalls, session.loginCalls, session.validateCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperConfigWriterWaitsForPINAndLogin(t *testing.T) {
	fixture := newHelperFixture(t)
	providerEntered := make(chan struct{}, 1)
	allowProvider := make(chan struct{}, 1)
	loginEntered := make(chan struct{}, 1)
	allowLogin := make(chan struct{}, 1)
	defer releasePersistentTestBlock(allowProvider)
	defer releasePersistentTestBlock(allowLogin)

	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	session.loginCheck = func() error {
		loginEntered <- struct{}{}
		<-allowLogin
		return nil
	}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.lockConfig = config.AcquireSharedLock
	deps.resolvePIN = func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error) {
		providerEntered <- struct{}{}
		<-allowProvider
		return []byte("123456"), nil
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	defer harness.requestWriter.Close()
	defer harness.responseReader.Close()
	requestID, _ := newRequestIdentifier()
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	waitPersistentTestSignal(t, providerEntered, "PIN provider")

	writerDone := startPersistentTestConfigWriter(harness.configPath, fixture.cfg)
	assertPersistentTestWriterBlocked(t, writerDone, "PIN provider")
	allowProvider <- struct{}{}
	waitPersistentTestSignal(t, loginEntered, "login")
	assertPersistentTestWriterBlocked(t, writerDone, "login")
	allowLogin <- struct{}{}
	assertPersistentTestWriterBlocked(t, writerDone, "readiness write")
	readPersistentTestReady(t, harness.responseReader, sessionID, requestID)
	waitPersistentTestWriter(t, writerDone)

	_ = harness.requestWriter.Close()
	result := waitPersistentTestHelperResult(t, harness.result)
	if result.code != helperFailureExitCode || session.loginCalls != 1 || session.deriveCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("result=%+v login=%d derive=%d close=%d", result, session.loginCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperConfigWriterWaitsForValidateAndReadiness(t *testing.T) {
	fixture := newHelperFixture(t)
	validateEntered := make(chan struct{}, 1)
	allowValidate := make(chan struct{}, 1)
	defer releasePersistentTestBlock(allowValidate)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	session.validateCheck = func() error {
		validateEntered <- struct{}{}
		<-allowValidate
		return nil
	}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.lockConfig = config.AcquireSharedLock
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	defer harness.requestWriter.Close()
	defer harness.responseReader.Close()
	requestID, _ := newRequestIdentifier()
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	waitPersistentTestSignal(t, validateEntered, "session validation")

	writerDone := startPersistentTestConfigWriter(harness.configPath, fixture.cfg)
	assertPersistentTestWriterBlocked(t, writerDone, "session validation")
	allowValidate <- struct{}{}
	assertPersistentTestWriterBlocked(t, writerDone, "readiness write")
	readPersistentTestReady(t, harness.responseReader, sessionID, requestID)
	waitPersistentTestWriter(t, writerDone)

	_ = harness.requestWriter.Close()
	result := waitPersistentTestHelperResult(t, harness.result)
	if result.code != helperFailureExitCode || session.validateCalls != 1 || session.deriveCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("result=%+v validate=%d derive=%d close=%d", result, session.validateCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperConfigWriterWaitsForDeriveAndResult(t *testing.T) {
	fixture := newHelperFixture(t)
	deriveEntered := make(chan struct{}, 1)
	allowDerive := make(chan struct{}, 1)
	defer releasePersistentTestBlock(allowDerive)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	session.deriveCheck = func() error {
		deriveEntered <- struct{}{}
		<-allowDerive
		return nil
	}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.lockConfig = config.AcquireSharedLock
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	defer harness.requestWriter.Close()
	defer harness.responseReader.Close()
	requestID, _ := newRequestIdentifier()
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	readPersistentTestReady(t, harness.responseReader, sessionID, requestID)
	continuationID := writePersistentTestContinue(t, harness.requestWriter, sessionID, requestID)
	waitPersistentTestSignal(t, deriveEntered, "derive")

	writerDone := startPersistentTestConfigWriter(harness.configPath, fixture.cfg)
	assertPersistentTestWriterBlocked(t, writerDone, "derive")
	allowDerive <- struct{}{}
	assertPersistentTestWriterBlocked(t, writerDone, "result write")
	fileKey := readPersistentTestResult(t, harness.responseReader, sessionID, requestID, continuationID)
	ClearSecret(fileKey)
	waitPersistentTestWriter(t, writerDone)

	_ = harness.requestWriter.Close()
	result := waitPersistentTestHelperResult(t, harness.result)
	if result.code != 0 || session.deriveCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("result=%+v derive=%d close=%d", result, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperConfigWriterRunsWhileWaitingForTouchAndInvalidatesContinue(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.lockConfig = config.AcquireSharedLock
	deps.loadConfig = func(path, home string) (config.Config, configSnapshotBinding, error) {
		return loadStableConfigSnapshotWith(path, home, func(string, string) (config.Config, error) {
			return fixture.cfg, nil
		}, os.Lstat)
	}
	deps.inspectConfig = inspectConfigSnapshot
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	defer harness.requestWriter.Close()
	defer harness.responseReader.Close()
	requestID, _ := newRequestIdentifier()
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	readPersistentTestReady(t, harness.responseReader, sessionID, requestID)

	writerDone := startPersistentTestConfigWriter(harness.configPath, fixture.cfg)
	waitPersistentTestWriter(t, writerDone)
	continuationID := writePersistentTestContinue(t, harness.requestWriter, sessionID, requestID)
	payload, err := readFrame(harness.responseReader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	_, resultErr := unmarshalSessionResult(payload, sessionID, requestID, continuationID)
	clear(payload)
	if ErrorClassOf(resultErr) != ErrorConfiguration {
		t.Fatalf("result class = %q", ErrorClassOf(resultErr))
	}
	result := waitPersistentTestHelperResult(t, harness.result)
	if result.code != helperFailureExitCode || session.loginCalls != 1 || session.deriveCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("result=%+v login=%d derive=%d close=%d", result, session.loginCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperPINFailureHasNoReadiness(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.resolvePIN = func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error) {
		return nil, classError(ErrorPINProvider)
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	payload, err := readFrame(harness.responseReader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	resultErr := unmarshalSessionEarlyResult(payload, sessionID, requestID)
	clear(payload)
	if ErrorClassOf(resultErr) != ErrorPINProvider {
		t.Fatalf("result class = %q", ErrorClassOf(resultErr))
	}
	result := <-harness.result
	_ = harness.requestWriter.Close()
	_ = harness.responseReader.Close()
	if !result.handled || result.code != helperFailureExitCode {
		t.Fatalf("helper result = %+v", result)
	}
	if session.loginCalls != 0 || session.validateCalls != 0 || session.deriveCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("login=%d validate=%d derive=%d close=%d", session.loginCalls, session.validateCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperLoginFailureHasNoReadiness(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{
		private:  fixture.hardwarePrivate,
		loginErr: agehardware.ErrPINLoginFailed,
	}
	deps := successfulPersistentHelperDependencies(fixture, session)
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	payload, err := readFrame(harness.responseReader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	resultErr := unmarshalSessionEarlyResult(payload, sessionID, requestID)
	clear(payload)
	if ErrorClassOf(resultErr) != ErrorHardwarePIN {
		t.Fatalf("result class = %q", ErrorClassOf(resultErr))
	}
	result := <-harness.result
	if err := ensureEOF(harness.responseReader); err != nil {
		t.Fatal("login failure emitted readiness or another trailing frame")
	}
	_ = harness.requestWriter.Close()
	_ = harness.responseReader.Close()
	if !result.handled || result.code != helperFailureExitCode {
		t.Fatalf("helper result = %+v", result)
	}
	if session.loginCalls != 1 || session.validateCalls != 0 || session.deriveCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("login=%d validate=%d derive=%d close=%d",
			session.loginCalls, session.validateCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperRejectsPINFromReplacedConfigSnapshot(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.loadConfig = func(path, home string) (config.Config, configSnapshotBinding, error) {
		return loadStableConfigSnapshotWith(path, home, func(string, string) (config.Config, error) {
			return fixture.cfg, nil
		}, os.Lstat)
	}
	deps.inspectConfig = inspectConfigSnapshot
	resolverRuns := 0
	providerCalls := 0
	deps.resolvePIN = func(
		ctx context.Context,
		configPath string,
		sessionID sessionIdentifier,
		requestID requestIdentifier,
		expectedBinding configSnapshotBinding,
	) ([]byte, error) {
		resolverRuns++
		atomicReplaceTestConfig(t, configPath, []byte("replacement target and PIN provider configuration"))
		var request bytes.Buffer
		if err := writePINResolverRequestFrame(&request, sessionID, requestID, expectedBinding); err != nil {
			return nil, err
		}
		var response bytes.Buffer
		newConfig := fixture.cfg
		newAge := *fixture.cfg.Age
		newAge.Serial = "2"
		newConfig.Age = &newAge
		newConfig.PINProvider = config.PINProvider1Password
		newConfig.OnePasswordAccount = "replacement-account"
		newConfig.OnePasswordRef = "op://Replacement/YubiKey/pin"
		resolverDeps := pinResolverDependencies{
			loadConfig: func(path, home string) (config.Config, configSnapshotBinding, error) {
				return loadStableConfigSnapshotWith(path, home, func(string, string) (config.Config, error) {
					return newConfig, nil
				}, os.Lstat)
			},
			resolvePIN: func(context.Context, config.Config) ([]byte, error) {
				providerCalls++
				return []byte("654321"), nil
			},
			disableCoreDump: func() error { return nil },
			verifyParent:    func() error { return nil },
			watchParentDeath: func(func(string) string) (func(), error) {
				return func() {}, nil
			},
		}
		handled, code := runPINResolverInternal(
			ctx,
			&request,
			&response,
			pinResolverTestEnvironment(configPath, sessionID, requestID),
			"/home/test",
			resolverDeps,
		)
		if !handled || code != helperFailureExitCode {
			return nil, classError(ErrorHelper)
		}
		return readPINResolverResponseFrame(&response, sessionID, requestID, expectedBinding)
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	payload, err := readFrame(harness.responseReader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	resultErr := unmarshalSessionEarlyResult(payload, sessionID, requestID)
	clear(payload)
	if ErrorClassOf(resultErr) != ErrorConfiguration {
		t.Fatalf("result class = %q", ErrorClassOf(resultErr))
	}
	result := <-harness.result
	if err := ensureEOF(harness.responseReader); err != nil {
		t.Fatal("snapshot mismatch emitted readiness or another trailing frame")
	}
	_ = harness.requestWriter.Close()
	_ = harness.responseReader.Close()
	if !result.handled || result.code != helperFailureExitCode {
		t.Fatalf("helper result = %+v", result)
	}
	if resolverRuns != 1 || providerCalls != 0 || session.loginCalls != 0 || session.validateCalls != 0 ||
		session.deriveCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("resolver=%d provider=%d login=%d validate=%d derive=%d close=%d",
			resolverRuns, providerCalls, session.loginCalls, session.validateCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperConfigReplacementInvalidatesRetainedSession(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.loadConfig = func(path, home string) (config.Config, configSnapshotBinding, error) {
		return loadStableConfigSnapshotWith(path, home, func(string, string) (config.Config, error) {
			return fixture.cfg, nil
		}, os.Lstat)
	}
	deps.inspectConfig = inspectConfigSnapshot
	resolverCalls := 0
	deps.resolvePIN = func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error) {
		resolverCalls++
		return []byte("123456"), nil
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	firstRequestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestRequest(t, harness.requestWriter, sessionID, firstRequestID, fixture.hardwareEnvelope)
	readPersistentTestReady(t, harness.responseReader, sessionID, firstRequestID)
	continuationID := writePersistentTestContinue(t, harness.requestWriter, sessionID, firstRequestID)
	ClearSecret(readPersistentTestResult(t, harness.responseReader, sessionID, firstRequestID, continuationID))

	atomicReplaceTestConfig(t, harness.configPath, []byte("replacement configuration after retained login"))
	secondRequestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestRequest(t, harness.requestWriter, sessionID, secondRequestID, fixture.hardwareEnvelope)
	payload, err := readFrame(harness.responseReader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	resultErr := unmarshalSessionEarlyResult(payload, sessionID, secondRequestID)
	clear(payload)
	if ErrorClassOf(resultErr) != ErrorConfiguration {
		t.Fatalf("result class = %q", ErrorClassOf(resultErr))
	}
	result := <-harness.result
	if err := ensureEOF(harness.responseReader); err != nil {
		t.Fatal("replaced retained snapshot emitted readiness or another trailing frame")
	}
	_ = harness.requestWriter.Close()
	_ = harness.responseReader.Close()
	if !result.handled || result.code != helperFailureExitCode {
		t.Fatalf("helper result = %+v", result)
	}
	if resolverCalls != 1 || session.loginCalls != 1 || session.validateCalls != 1 ||
		session.deriveCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("resolver=%d login=%d validate=%d derive=%d close=%d",
			resolverCalls, session.loginCalls, session.validateCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperLogsInOnlyAfterResolverIsReaped(t *testing.T) {
	fixture := newHelperFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	resolverConfig := filepath.Join(t.TempDir(), pinResolverProcessChildPrefix+"wait-marker")
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	session.loginCheck = func() error {
		resolverPID := readPIDFile(t, resolverConfig+".self.pid")
		if err := syscall.Kill(resolverPID, 0); !errors.Is(err, syscall.ESRCH) {
			return errors.New("resolver was not reaped before login")
		}
		return nil
	}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.resolvePIN = func(ctx context.Context, _ string, sessionID sessionIdentifier, requestID requestIdentifier, binding configSnapshotBinding) ([]byte, error) {
		return resolvePINWithProcess(ctx, executable, resolverConfig, os.Environ(), sessionID, requestID, binding, func(path string) *exec.Cmd {
			return exec.Command(path)
		})
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	requestID, _ := newRequestIdentifier()
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	readPersistentTestReady(t, harness.responseReader, sessionID, requestID)
	continuationID := writePersistentTestContinue(t, harness.requestWriter, sessionID, requestID)
	ClearSecret(readPersistentTestResult(t, harness.responseReader, sessionID, requestID, continuationID))
	_ = harness.requestWriter.Close()
	result := <-harness.result
	_ = harness.responseReader.Close()
	if result.code != 0 || session.loginCalls != 1 {
		t.Fatalf("helper result=%+v login=%d", result, session.loginCalls)
	}
}

func TestPersistentHardwareHelperRejectsDuplicateRequestID(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	readPersistentTestReady(t, harness.responseReader, sessionID, requestID)
	continuationID := writePersistentTestContinue(t, harness.requestWriter, sessionID, requestID)
	ClearSecret(readPersistentTestResult(t, harness.responseReader, sessionID, requestID, continuationID))

	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	payload, err := readFrame(harness.responseReader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	resultErr := unmarshalSessionEarlyResult(payload, sessionID, requestID)
	clear(payload)
	if ErrorClassOf(resultErr) != ErrorInvalidRequest {
		t.Fatalf("duplicate class = %q", ErrorClassOf(resultErr))
	}
	result := <-harness.result
	_ = harness.requestWriter.Close()
	_ = harness.responseReader.Close()
	if result.code != helperFailureExitCode || session.deriveCalls != 1 {
		t.Fatalf("helper result = %+v, derives=%d", result, session.deriveCalls)
	}
}

func TestPersistentHardwareHelperReplayCapacityFailsBeforeNewHardwareWork(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	deps.replayLimit = 1
	resolverCalls := 0
	deps.resolvePIN = func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error) {
		resolverCalls++
		return []byte("123456"), nil
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	firstID, _ := newRequestIdentifier()
	writePersistentTestRequest(t, harness.requestWriter, sessionID, firstID, fixture.hardwareEnvelope)
	readPersistentTestReady(t, harness.responseReader, sessionID, firstID)
	continuationID := writePersistentTestContinue(t, harness.requestWriter, sessionID, firstID)
	ClearSecret(readPersistentTestResult(t, harness.responseReader, sessionID, firstID, continuationID))

	secondID, _ := newRequestIdentifier()
	writePersistentTestRequest(t, harness.requestWriter, sessionID, secondID, fixture.hardwareEnvelope)
	payload, err := readFrame(harness.responseReader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	resultErr := unmarshalSessionEarlyResult(payload, sessionID, secondID)
	clear(payload)
	if ErrorClassOf(resultErr) != ErrorHelper {
		t.Fatalf("capacity class = %q", ErrorClassOf(resultErr))
	}
	result := <-harness.result
	_ = harness.requestWriter.Close()
	_ = harness.responseReader.Close()
	if result.code != helperFailureExitCode || resolverCalls != 1 || session.loginCalls != 1 ||
		session.validateCalls != 1 || session.deriveCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("result=%+v resolver=%d login=%d validate=%d derive=%d close=%d",
			result, resolverCalls, session.loginCalls, session.validateCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPersistentHardwareHelperRejectsWrongContinueID(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestRequest(t, harness.requestWriter, sessionID, requestID, fixture.hardwareEnvelope)
	readPersistentTestReady(t, harness.responseReader, sessionID, requestID)
	wrongID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	writePersistentTestContinue(t, harness.requestWriter, sessionID, wrongID)
	if payload, err := readFrame(harness.responseReader, maxSessionResponseFrame); err == nil {
		clear(payload)
		t.Fatal("malformed continue unexpectedly produced a result")
	}
	result := <-harness.result
	_ = harness.requestWriter.Close()
	_ = harness.responseReader.Close()
	if result.code != helperFailureExitCode || session.deriveCalls != 0 {
		t.Fatalf("helper result = %+v, derives=%d", result, session.deriveCalls)
	}
}

func TestPersistentHardwareHelperRejectsMissingRequestIDBeforeSideEffects(t *testing.T) {
	fixture := newHelperFixture(t)
	session := &fakeRetainedSession{private: fixture.hardwarePrivate}
	deps := successfulPersistentHelperDependencies(fixture, session)
	loadCalls := 0
	openCalls := 0
	resolverCalls := 0
	deps.loadConfig = func(string, string) (config.Config, configSnapshotBinding, error) {
		loadCalls++
		return fixture.cfg, fixedConfigSnapshotBinding(), nil
	}
	deps.openSession = func(context.Context, config.Config, agehardware.Target) (retainedHardwareSession, error) {
		openCalls++
		return session, nil
	}
	deps.resolvePIN = func(context.Context, string, sessionIdentifier, requestIdentifier, configSnapshotBinding) ([]byte, error) {
		resolverCalls++
		return []byte("123456"), nil
	}
	harness, sessionID := startPersistentHelperHarness(t, fixture, deps)
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := marshalSessionRequest(sessionID, requestID, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	requestField := []byte(`"request_id":"` + hex.EncodeToString(requestID[:]) + `",`)
	mutation := bytes.Replace(payload, requestField, nil, 1)
	clear(payload)
	if bytes.Equal(mutation, payload) || bytes.Contains(mutation, []byte(`"request_id"`)) {
		clear(mutation)
		t.Fatal("failed to remove request_id from the fixture")
	}
	if err := writeFrame(harness.requestWriter, mutation, maxSessionRequestFrame); err != nil {
		clear(mutation)
		t.Fatal(err)
	}
	clear(mutation)
	result := <-harness.result
	_ = harness.requestWriter.Close()
	if payload, err := readFrame(harness.responseReader, maxSessionResponseFrame); err == nil {
		clear(payload)
		t.Fatal("invalid request unexpectedly produced a response frame")
	}
	_ = harness.responseReader.Close()
	if result.code != helperFailureExitCode || loadCalls != 0 || openCalls != 0 || resolverCalls != 0 ||
		session.loginCalls != 0 || session.deriveCalls != 0 || session.closeCalls != 0 {
		t.Fatalf("result=%+v load=%d open=%d resolver=%d login=%d derive=%d close=%d",
			result, loadCalls, openCalls, resolverCalls, session.loginCalls, session.deriveCalls, session.closeCalls)
	}
}

func TestPINResolverInternalReturnsBoundMutablePIN(t *testing.T) {
	sessionID, err := newSessionIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	request := &bytes.Buffer{}
	binding := fixedConfigSnapshotBinding()
	if err := writePINResolverRequestFrame(request, sessionID, requestID, binding); err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	configPath := filepath.Join(t.TempDir(), "config.json")
	getenv := pinResolverTestEnvironment(configPath, sessionID, requestID)
	deps := pinResolverDependencies{
		loadConfig: func(string, string) (config.Config, configSnapshotBinding, error) {
			return config.Config{Age: &config.AgeConfig{}}, binding, nil
		},
		resolvePIN:      func(context.Context, config.Config) ([]byte, error) { return []byte("123456"), nil },
		disableCoreDump: func() error { return nil },
		verifyParent:    func() error { return nil },
		watchParentDeath: func(func(string) string) (func(), error) {
			return func() {}, nil
		},
	}
	handled, code := runPINResolverInternal(context.Background(), request, &response, getenv, "/home/test", deps)
	if !handled || code != 0 {
		t.Fatalf("handled=%t code=%d", handled, code)
	}
	pinValue, err := readPINResolverResponseFrame(&response, sessionID, requestID, binding)
	if err != nil || string(pinValue) != "123456" {
		t.Fatalf("PIN response length=%d err=%v", len(pinValue), err)
	}
	secureClear(pinValue)
}

func writePersistentTestRequest(
	t *testing.T,
	writer io.Writer,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	envelope ageprofile.Envelope,
) {
	t.Helper()
	payload, err := marshalSessionRequest(sessionID, requestID, Request{Envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if err := writeFrame(writer, payload, maxSessionRequestFrame); err != nil {
		t.Fatal(err)
	}
}

func readPersistentTestReady(
	t *testing.T,
	reader io.Reader,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
) {
	t.Helper()
	ready, err := readFrame(reader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	if err := unmarshalSessionReady(ready, sessionID, requestID); err != nil {
		clear(ready)
		t.Fatal(err)
	}
	clear(ready)
	touch, err := readFrame(reader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	if err := unmarshalSessionReadyForTouch(touch, sessionID, requestID); err != nil {
		clear(touch)
		t.Fatal(err)
	}
	clear(touch)
}

func writePersistentTestContinue(
	t *testing.T,
	writer io.Writer,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
) continuationIdentifier {
	t.Helper()
	continuationID, err := newContinuationIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := marshalSessionContinue(sessionID, requestID, continuationID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if err := writeFrame(writer, payload, maxSessionResponseFrame); err != nil {
		t.Fatal(err)
	}
	return continuationID
}

func readPersistentTestResult(
	t *testing.T,
	reader io.Reader,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	continuationID continuationIdentifier,
) []byte {
	t.Helper()
	payload, err := readFrame(reader, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := unmarshalSessionResult(payload, sessionID, requestID, continuationID)
	clear(payload)
	if err != nil {
		t.Fatal(err)
	}
	return fileKey
}

func pinResolverTestEnvironment(
	configPath string,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
) func(string) string {
	return func(name string) string {
		switch name {
		case internalModeEnvironment:
			return internalPINResolverMode
		case sessionIDEnvironment:
			return hex.EncodeToString(sessionID[:])
		case requestIDEnvironment:
			return hex.EncodeToString(requestID[:])
		case "YUBITOUCH_CONFIG":
			return configPath
		default:
			return ""
		}
	}
}

func releasePersistentTestBlock(block chan<- struct{}) {
	select {
	case block <- struct{}{}:
	default:
	}
}

func waitPersistentTestSignal(t *testing.T, signal <-chan struct{}, stage string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("helper did not reach %s", stage)
	}
}

func startPersistentTestConfigWriter(path string, cfg config.Config) <-chan error {
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- config.Save(path, cfg)
	}()
	<-started
	return done
}

func assertPersistentTestWriterBlocked(t *testing.T, done <-chan error, stage string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("configuration writer completed during %s: %v", stage, err)
	case <-time.After(75 * time.Millisecond):
	}
}

func waitPersistentTestWriter(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("configuration writer failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("configuration writer remained blocked")
	}
}

func waitPersistentTestHelperResult(t *testing.T, result <-chan helperRunResult) helperRunResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("persistent helper did not exit")
		return helperRunResult{}
	}
}

func atomicReplaceTestConfig(t *testing.T, path string, contents []byte) {
	t.Helper()
	replacement := filepath.Join(filepath.Dir(path), ".replacement-config.json")
	if err := os.WriteFile(replacement, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
}
