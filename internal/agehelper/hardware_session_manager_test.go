package agehelper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const hardwareManagerChildPrefix = "session-manager-child-"
const pinResolverProcessChildPrefix = "pin-resolver-child-"

func runHardwareManagerTestChild(configPath string) int {
	stopParentWatch, err := startParentLifetimeWatch(os.Getenv)
	if err != nil {
		return 70
	}
	defer stopParentWatch()
	sessionID, err := parseSessionIdentifier(os.Getenv(sessionIDEnvironment))
	if err != nil {
		return 71
	}
	action := strings.TrimPrefix(filepath.Base(configPath), hardwareManagerChildPrefix)
	reader := bufio.NewReaderSize(os.Stdin, maxSessionRequestFrame+4)
	for {
		if _, err := reader.Peek(1); errors.Is(err, io.EOF) {
			return 0
		} else if err != nil {
			return 72
		}
		payload, err := readFrame(reader, maxSessionRequestFrame)
		if err != nil {
			return 73
		}
		requestID, _, err := unmarshalSessionRequest(payload, sessionID)
		clear(payload)
		if err != nil {
			return 74
		}
		if action == "request-marker" {
			if err := os.WriteFile(configPath+".request", []byte("request received"), 0o600); err != nil {
				return 88
			}
		}
		switch action {
		case "crash":
			return 75
		case "oversized":
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], maxSessionResponseFrame+1)
			_, _ = os.Stdout.Write(header[:])
			return 0
		case "hang-before":
			return hangRunnerTestChild(configPath)
		case "nested-resolver-hang":
			executable, executableErr := os.Executable()
			if executableErr != nil {
				return 82
			}
			resolverConfig := filepath.Join(filepath.Dir(configPath), pinResolverProcessChildPrefix+"hang-nested")
			pinValue, resolverErr := resolvePINWithProcess(
				context.Background(), executable, resolverConfig, os.Environ(), sessionID, requestID,
				fixedConfigSnapshotBinding(),
				func(path string) *exec.Cmd { return exec.Command(path) },
			)
			secureClear(pinValue)
			if resolverErr != nil {
				return helperFailureExitCode
			}
			return 83
		case "nested-resolver-crash":
			executable, executableErr := os.Executable()
			if executableErr != nil {
				return 84
			}
			resolverConfig := filepath.Join(filepath.Dir(configPath), pinResolverProcessChildPrefix+"hang-nested-crash")
			go func() {
				pinValue, _ := resolvePINWithProcess(
					context.Background(), executable, resolverConfig, os.Environ(), sessionID, requestID,
					fixedConfigSnapshotBinding(),
					func(path string) *exec.Cmd { return exec.Command(path) },
				)
				secureClear(pinValue)
			}()
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				_, selfErr := os.Stat(resolverConfig + ".self.pid")
				_, childErr := os.Stat(resolverConfig + ".pid")
				if selfErr == nil && childErr == nil {
					return 85
				}
				time.Sleep(time.Millisecond)
			}
			return 86
		case "pin-failure":
			_ = writeSessionEarlyResult(os.Stdout, sessionID, requestID, ErrorPINProvider)
			return helperFailureExitCode
		case "ready-before-session":
			_ = writeSessionControl(os.Stdout, marshalSessionReadyForTouch, sessionID, requestID)
			return helperFailureExitCode
		case "wrong-session":
			wrong := sessionID
			wrong[0] ^= 0xff
			_ = writeSessionControl(os.Stdout, marshalSessionReady, wrong, requestID)
			return helperFailureExitCode
		case "wrong-request":
			wrong := requestID
			wrong[0] ^= 0xff
			_ = writeSessionControl(os.Stdout, marshalSessionReady, sessionID, wrong)
			return helperFailureExitCode
		}
		if err := writeSessionControl(os.Stdout, marshalSessionReady, sessionID, requestID); err != nil {
			return 76
		}
		if action == "duplicate-session" {
			_ = writeSessionControl(os.Stdout, marshalSessionReady, sessionID, requestID)
			return helperFailureExitCode
		}
		if action == "hang-session-ready" {
			return hangRunnerTestChild(configPath)
		}
		if err := writeSessionControl(os.Stdout, marshalSessionReadyForTouch, sessionID, requestID); err != nil {
			return 77
		}
		if action == "result-before-continue" {
			forged, _ := newContinuationIdentifier()
			_ = writeSessionResult(os.Stdout, sessionID, requestID, forged, []byte("runner-file-key!"), "")
			return 87
		}
		if action == "hang-ready" {
			return hangRunnerTestChild(configPath)
		}
		continued, err := readFrame(reader, maxSessionResponseFrame)
		if err != nil {
			return 78
		}
		continuationID, err := unmarshalSessionContinue(continued, sessionID, requestID)
		clear(continued)
		if err != nil {
			return 79
		}
		if action == "hang-result" {
			return hangRunnerTestChild(configPath)
		}
		resultSessionID := sessionID
		resultRequestID := requestID
		if action == "wrong-result-session" {
			resultSessionID[0] ^= 0xff
		}
		if action == "wrong-result-request" {
			resultRequestID[0] ^= 0xff
		}
		if action == "result-error" {
			_ = writeSessionResult(os.Stdout, resultSessionID, resultRequestID, continuationID, nil, ErrorHardware)
			return helperFailureExitCode
		}
		if err := writeSessionResult(os.Stdout, resultSessionID, resultRequestID, continuationID, []byte("runner-file-key!"), ""); err != nil {
			return 80
		}
		if action == "idle-output" {
			_ = writeSessionControl(os.Stdout, marshalSessionReady, sessionID, requestID)
		}
		if action == "idle-crash" || action == "wrong-result-session" || action == "wrong-result-request" {
			return 81
		}
	}
}

func runPINResolverProcessTestChild(configPath string) int {
	var stopParentWatch func()
	var err error
	if os.Getenv(resolverGroupEnvironment) == resolverGroupInherited {
		stopParentWatch, err = startResolverParentLifetimeWatch(os.Getenv)
	} else {
		stopParentWatch, err = startParentLifetimeWatch(os.Getenv)
	}
	if err != nil {
		return 90
	}
	defer stopParentWatch()
	sessionID, err := parseSessionIdentifier(os.Getenv(sessionIDEnvironment))
	if err != nil {
		return 91
	}
	requestID, err := parseRequestIdentifier(os.Getenv(requestIDEnvironment))
	if err != nil {
		return 92
	}
	binding, err := readPINResolverRequestFrame(os.Stdin, sessionID, requestID)
	if err != nil {
		return 93
	}
	action := strings.TrimPrefix(filepath.Base(configPath), pinResolverProcessChildPrefix)
	if strings.HasPrefix(action, "hang") {
		if err := os.WriteFile(configPath+".self.pid", []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			return 96
		}
		return hangRunnerTestChild(configPath)
	}
	if action == "provider-error" {
		_ = writePINResolverResponseFrame(os.Stdout, sessionID, requestID, binding, nil, ErrorPINProvider)
		return helperFailureExitCode
	}
	if err := writePINResolverResponseFrame(os.Stdout, sessionID, requestID, binding, []byte("123456"), ""); err != nil {
		return 94
	}
	if action == "response-then-hang" {
		if err := os.Stdout.Close(); err != nil {
			return 98
		}
		if err := os.WriteFile(configPath+".self.pid", []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			return 99
		}
		for {
			time.Sleep(time.Second)
		}
	}
	if action == "wait-marker" {
		if err := os.WriteFile(configPath+".self.pid", []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			return 97
		}
		if err := os.WriteFile(configPath+".exited", []byte("resolver exited"), 0o600); err != nil {
			return 95
		}
	}
	return 0
}

func TestHardwareManagerReusesProcessAndConsumesEachResultOnce(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	defer manager.Close()
	var firstProcess *hardwareProcess
	for requestNumber := 0; requestNumber < 2; requestNumber++ {
		call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
		if err != nil {
			t.Fatal(err)
		}
		if err := call.WaitReady(); err != nil {
			t.Fatal(err)
		}
		fileKey, err := call.Wait()
		if err != nil || string(fileKey) != "runner-file-key!" {
			t.Fatalf("result=%q err=%v", fileKey, err)
		}
		ClearSecret(fileKey)
		if repeated, err := call.Wait(); ErrorClassOf(err) != ErrorHelper || len(repeated) != 0 {
			ClearSecret(repeated)
			t.Fatalf("repeated Wait result=%x class=%q", repeated, ErrorClassOf(err))
		}
		if requestNumber == 0 {
			firstProcess = call.process
		} else if call.process != firstProcess {
			t.Fatal("successful request did not reuse the helper process")
		}
	}
	if firstProcess == nil || firstProcess.isStopped() {
		t.Fatal("successful helper was not retained")
	}
}

func TestHardwareManagerCompletedCallContextCannotStopReusedProcess(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	defer manager.Close()
	firstContext, cancelFirst := context.WithCancel(context.Background())
	first, err := manager.Start(firstContext, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := first.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	second, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if second.process != first.process {
		t.Fatal("second request did not reuse the retained helper")
	}
	if err := second.WaitReady(); err != nil {
		t.Fatal(err)
	}
	cancelFirst()
	fileKey, err = second.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatalf("completed call context stopped the reused helper: %v", err)
	}
}

func TestHardwareManagerRejectsMalformedOrderAndIdentifiers(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, action := range []string{
		"crash", "oversized", "ready-before-session", "wrong-session", "wrong-request", "duplicate-session",
		"wrong-result-session", "wrong-result-request", "result-before-continue",
	} {
		t.Run(action, func(t *testing.T) {
			manager := testHardwareManager(t, action, 10*time.Second)
			call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
			if err != nil {
				t.Fatal(err)
			}
			pid := call.process.cmd.Process.Pid
			if action == "wrong-result-session" || action == "wrong-result-request" || action == "result-before-continue" {
				if err := call.WaitReady(); err != nil {
					t.Fatal(err)
				}
				_, err = call.Wait()
			} else {
				err = call.WaitReady()
			}
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
			assertProcessGone(t, pid, "persistent helper", "")
			_ = manager.Close()
		})
	}
}

func TestHardwareManagerEarlyPINFailureHasNoReadyState(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "pin-failure", 10*time.Second)
	call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	pid := call.process.cmd.Process.Pid
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorPINProvider {
		t.Fatalf("error class = %q", ErrorClassOf(err))
	}
	assertProcessGone(t, pid, "persistent helper", "")
	_ = manager.Close()
}

func TestHardwareManagerConsecutiveFailuresAllowImmediateRestart(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "pin-failure", 10*time.Second)
	defer manager.Close()
	for attempt := 0; attempt < 3; attempt++ {
		call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
		if err != nil {
			t.Fatalf("Start attempt %d: %v", attempt, err)
		}
		pid := call.process.cmd.Process.Pid
		if err := call.WaitReady(); ErrorClassOf(err) != ErrorPINProvider {
			t.Fatalf("attempt %d error class = %q", attempt, ErrorClassOf(err))
		}
		manager.mu.Lock()
		active := manager.active
		manager.mu.Unlock()
		if active != nil {
			t.Fatalf("attempt %d returned before the failed call released the manager", attempt)
		}
		assertProcessGone(t, pid, "persistent helper", "")
	}
}

func TestHardwareCallFailurePublishesReadyAfterWatcherJoin(t *testing.T) {
	manager := &HardwareManager{}
	process := &hardwareProcess{}
	delivery := &processDelivery{done: make(chan struct{})}
	call := &HardwareCall{
		manager:   manager,
		process:   process,
		delivery:  delivery,
		cancel:    func() {},
		readyDone: make(chan struct{}),
		done:      make(chan struct{}),
		watchStop: make(chan struct{}),
		watchDone: make(chan struct{}),
	}
	manager.process = process
	manager.active = call
	finished := make(chan struct{})
	go func() {
		call.finish(nil, classError(ErrorHelper), false)
		close(finished)
	}()

	<-call.watchStop
	select {
	case <-call.readyDone:
		t.Fatal("WaitReady failure was published before the context watcher joined")
	default:
	}
	manager.mu.Lock()
	active := manager.active
	manager.mu.Unlock()
	if active != call {
		t.Fatal("manager became reusable before the old context watcher joined")
	}
	close(call.watchDone)
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("call did not finish after the context watcher joined")
	}
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("error class = %q", ErrorClassOf(err))
	}
	manager.mu.Lock()
	active = manager.active
	manager.mu.Unlock()
	if active != nil {
		t.Fatal("manager remained active after failure publication")
	}
}

func TestHardwareManagerRegisterFailureReapsBeforeStartReturns(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	process, err := manager.launchProcess()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := process.register(); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.process = process
	manager.mu.Unlock()

	pid := process.cmd.Process.Pid
	if _, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope}); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("Start error class = %q", ErrorClassOf(err))
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("helper process %d still exists after Start returned: %v", pid, err)
	}
	if err := syscall.Kill(-pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("helper process group %d still exists after Start returned: %v", pid, err)
	}
	_ = manager.Close()
}

func TestHardwareManagerCancellationReapsEveryProtocolStage(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, action := range []string{"hang-before", "hang-session-ready", "hang-ready", "hang-result"} {
		t.Run(action, func(t *testing.T) {
			manager := testHardwareManager(t, action, 10*time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			call, err := manager.Start(ctx, Request{Envelope: fixture.hardwareEnvelope})
			if err != nil {
				t.Fatal(err)
			}
			helperPID := call.process.cmd.Process.Pid
			if action == "hang-ready" || action == "hang-result" {
				if err := call.WaitReady(); err != nil {
					t.Fatal(err)
				}
			}
			var waitResult chan error
			if action == "hang-ready" || action == "hang-result" {
				waitResult = make(chan error, 1)
				go func() {
					fileKey, err := call.Wait()
					ClearSecret(fileKey)
					waitResult <- err
				}()
			}
			pidPath := manager.configPath + ".pid"
			_ = waitForPIDFile(t, pidPath)
			cancel()
			if waitResult != nil {
				err = <-waitResult
			} else {
				err = call.WaitReady()
			}
			if ErrorClassOf(err) != ErrorCanceled {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
			assertProcessGone(t, helperPID, "persistent helper", "")
			assertChildGone(t, pidPath)
			_ = manager.Close()
		})
	}
}

func TestHardwareManagerTimeoutReapsHelper(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "hang-before", 100*time.Millisecond)
	call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	helperPID := call.process.cmd.Process.Pid
	pidPath := manager.configPath + ".pid"
	_ = waitForPIDFile(t, pidPath)
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorTimeout {
		t.Fatalf("error class = %q", ErrorClassOf(err))
	}
	assertProcessGone(t, helperPID, "persistent helper", "")
	assertChildGone(t, pidPath)
	_ = manager.Close()
}

func TestHardwareManagerInvalidateStartsFreshProcess(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	first, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := first.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	firstPID := first.process.cmd.Process.Pid
	manager.Invalidate()
	assertProcessGone(t, firstPID, "persistent helper", "")
	second, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err = second.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	if second.process == first.process || second.process.cmd.Process.Pid == firstPID {
		t.Fatal("invalidation reused the old helper")
	}
	_ = manager.Close()
}

func TestHardwareManagerRequestLimitReapsBeforeStartingReplacement(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	manager.requestLimit = 1
	first, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := first.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	firstPID := first.process.cmd.Process.Pid
	second, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(firstPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("old helper still existed when replacement Start returned: %v", err)
	}
	fileKey, err = second.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = manager.Close()
}

func TestHardwareManagerCancellationDuringRolloverDoesNotLaunchReplacement(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	manager.requestLimit = 1
	first, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := first.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	firstPID := first.process.cmd.Process.Pid
	entered := make(chan struct{})
	release := make(chan struct{})
	setHardwareProcessWaitGroup(first.process, func(int, time.Duration) bool {
		close(entered)
		<-release
		return true
	})
	launches := 0
	manager.command = func(path string) *exec.Cmd {
		launches++
		return exec.Command(path)
	}
	ctx, cancel := context.WithCancel(context.Background())
	type startResult struct {
		call *HardwareCall
		err  error
	}
	started := make(chan startResult, 1)
	go func() {
		call, err := manager.Start(ctx, Request{Envelope: fixture.hardwareEnvelope})
		started <- startResult{call: call, err: err}
	}()
	<-entered
	cancel()
	close(release)
	result := <-started
	if result.call != nil || ErrorClassOf(result.err) != ErrorCanceled {
		t.Fatalf("Start result call=%p class=%q", result.call, ErrorClassOf(result.err))
	}
	if launches != 0 {
		t.Fatalf("launched %d replacement helpers after rollover cancellation", launches)
	}
	assertProcessGone(t, firstPID, "persistent helper", "")
	_ = manager.Close()
}

func TestHardwareManagerCancellationDuringLaunchReapsWithoutSendingRequest(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "request-marker", 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	var launchedCommand *exec.Cmd
	manager.command = func(path string) *exec.Cmd {
		launchedCommand = exec.Command(path)
		close(entered)
		<-release
		return launchedCommand
	}
	type startResult struct {
		call *HardwareCall
		err  error
	}
	started := make(chan startResult, 1)
	go func() {
		call, err := manager.Start(ctx, Request{Envelope: fixture.hardwareEnvelope})
		started <- startResult{call: call, err: err}
	}()
	<-entered
	cancel()
	close(release)
	result := <-started
	if result.call != nil || ErrorClassOf(result.err) != ErrorCanceled {
		t.Fatalf("Start result call=%p class=%q", result.call, ErrorClassOf(result.err))
	}
	if launchedCommand == nil || launchedCommand.Process == nil {
		t.Fatal("launch cancellation test did not start a helper")
	}
	assertProcessGone(t, launchedCommand.Process.Pid, "persistent helper", "")
	if _, err := os.Stat(manager.configPath + ".request"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled Start sent a request to the helper: %v", err)
	}
	_ = manager.Close()
}

func TestHardwareManagerSerializesStartWithInvalidate(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	first, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := first.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	setHardwareProcessWaitGroup(first.process, func(int, time.Duration) bool {
		close(entered)
		<-release
		return true
	})
	invalidateResult := make(chan error, 1)
	go func() { invalidateResult <- manager.Invalidate() }()
	<-entered
	type startResult struct {
		call *HardwareCall
		err  error
	}
	started := make(chan startResult, 1)
	go func() {
		call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
		started <- startResult{call: call, err: err}
	}()
	select {
	case <-started:
		t.Fatal("Start passed Invalidate before old process-group confirmation")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-invalidateResult; err != nil {
		t.Fatal(err)
	}
	result := <-started
	if result.err != nil {
		t.Fatal(result.err)
	}
	fileKey, err = result.call.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = manager.Close()
}

func TestHardwareManagerCleanupFailurePoisonsManager(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := call.Wait()
	ClearSecret(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	setHardwareProcessWaitGroup(call.process, func(int, time.Duration) bool { return false })
	if err := manager.Invalidate(); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("cleanup class = %q", ErrorClassOf(err))
	}
	if _, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope}); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("poisoned Start class = %q", ErrorClassOf(err))
	}
	if err := manager.Close(); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("poisoned Close class = %q", ErrorClassOf(err))
	}
}

func TestHardwareManagerCallReportsCleanupFailureAndPoisonsManager(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "hang-before", 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	call, err := manager.Start(ctx, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForPIDFile(t, manager.configPath+".pid")
	setHardwareProcessWaitGroup(call.process, func(int, time.Duration) bool { return false })
	cancel()
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("cleanup class = %q", ErrorClassOf(err))
	}
	if _, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope}); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("poisoned Start class = %q", ErrorClassOf(err))
	}
	_ = manager.Close()
}

func TestHardwareManagerReapsIdleCrashAndUnexpectedOutput(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, action := range []string{"idle-crash", "idle-output"} {
		t.Run(action, func(t *testing.T) {
			manager := testHardwareManager(t, action, 10*time.Second)
			call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
			if err != nil {
				t.Fatal(err)
			}
			pid := call.process.cmd.Process.Pid
			fileKey, err := call.Wait()
			ClearSecret(fileKey)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-call.process.stopped:
			case <-time.After(3 * time.Second):
				t.Fatal("idle protocol failure was not reaped")
			}
			assertProcessGone(t, pid, "persistent helper", "")
			_ = manager.Close()
		})
	}
}

func TestPINResolverProcessWaitsForExitAndReaps(t *testing.T) {
	sessionID, err := newSessionIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), pinResolverProcessChildPrefix+"wait-marker")
	pinValue, err := resolvePINWithProcess(context.Background(), executable, configPath, os.Environ(), sessionID, requestID, fixedConfigSnapshotBinding(), func(path string) *exec.Cmd {
		return exec.Command(path)
	})
	if err != nil || string(pinValue) != "123456" {
		secureClear(pinValue)
		t.Fatalf("PIN length=%d err=%v", len(pinValue), err)
	}
	secureClear(pinValue)
	if _, err := os.Stat(configPath + ".exited"); err != nil {
		t.Fatal("resolver returned before its exit marker was written")
	}
	resolverPID := readPIDFile(t, configPath+".self.pid")
	if err := syscall.Kill(resolverPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("resolver process %d was not reaped before return: %v", resolverPID, err)
	}
}

func TestPINResolverProcessPreservesSafeProviderClass(t *testing.T) {
	sessionID, _ := newSessionIdentifier()
	requestID, _ := newRequestIdentifier()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), pinResolverProcessChildPrefix+"provider-error")
	_, err = resolvePINWithProcess(context.Background(), executable, configPath, os.Environ(), sessionID, requestID, fixedConfigSnapshotBinding(), func(path string) *exec.Cmd {
		return exec.Command(path)
	})
	if ErrorClassOf(err) != ErrorPINProvider {
		t.Fatalf("error class = %q", ErrorClassOf(err))
	}
}

func TestPINResolverProcessCancellationAndTimeoutCoverWait(t *testing.T) {
	for _, test := range []struct {
		name       string
		want       ErrorClass
		newContext func() (context.Context, context.CancelFunc)
		cancelNow  bool
	}{
		{
			name: "cancellation", want: ErrorCanceled, cancelNow: true,
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
		{
			name: "timeout", want: ErrorTimeout,
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 2*time.Second)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sessionID, _ := newSessionIdentifier()
			requestID, _ := newRequestIdentifier()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), pinResolverProcessChildPrefix+"response-then-hang")
			ctx, cancel := test.newContext()
			defer cancel()
			type resolverResult struct {
				pinValue []byte
				err      error
			}
			result := make(chan resolverResult, 1)
			go func() {
				pinValue, err := resolvePINWithProcess(ctx, executable, configPath, os.Environ(), sessionID, requestID, fixedConfigSnapshotBinding(), func(path string) *exec.Cmd {
					return exec.Command(path)
				})
				result <- resolverResult{pinValue: pinValue, err: err}
			}()
			resolverPID := waitForPIDFile(t, configPath+".self.pid")
			if test.cancelNow {
				cancel()
			}
			var got resolverResult
			select {
			case got = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("resolver cancellation did not interrupt Cmd.Wait")
			}
			secureClear(got.pinValue)
			if ErrorClassOf(got.err) != test.want {
				t.Fatalf("error class = %q, want %q", ErrorClassOf(got.err), test.want)
			}
			assertProcessGone(t, resolverPID, "PIN resolver", "")
			if err := syscall.Kill(-resolverPID, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("resolver process group %d still exists after return: %v", resolverPID, err)
			}
		})
	}
}

func TestHardwareManagerCancellationReapsNestedResolverBeforeReturn(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "nested-resolver-hang", 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	call, err := manager.Start(ctx, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	outerPID := call.process.cmd.Process.Pid
	resolverConfig := filepath.Join(filepath.Dir(manager.configPath), pinResolverProcessChildPrefix+"hang-nested")
	resolverPID := waitForPIDFile(t, resolverConfig+".self.pid")
	grandchildPID := waitForPIDFile(t, resolverConfig+".pid")
	cancel()
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorCanceled {
		t.Fatalf("error class = %q", ErrorClassOf(err))
	}
	assertNestedTopologyGone(t, outerPID, resolverPID, grandchildPID)
	_ = manager.Close()
}

func TestHardwareManagerTimeoutReapsNestedResolverBeforeReturn(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "nested-resolver-hang", 2*time.Second)
	call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	outerPID := call.process.cmd.Process.Pid
	resolverConfig := filepath.Join(filepath.Dir(manager.configPath), pinResolverProcessChildPrefix+"hang-nested")
	resolverPID := waitForPIDFile(t, resolverConfig+".self.pid")
	grandchildPID := waitForPIDFile(t, resolverConfig+".pid")
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorTimeout {
		t.Fatalf("error class = %q", ErrorClassOf(err))
	}
	assertNestedTopologyGone(t, outerPID, resolverPID, grandchildPID)
	_ = manager.Close()
}

func TestHardwareManagerOuterCrashReapsNestedResolverBeforeReturn(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "nested-resolver-crash", 10*time.Second)
	call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	outerPID := call.process.cmd.Process.Pid
	resolverConfig := filepath.Join(filepath.Dir(manager.configPath), pinResolverProcessChildPrefix+"hang-nested-crash")
	resolverPID := waitForPIDFile(t, resolverConfig+".self.pid")
	grandchildPID := waitForPIDFile(t, resolverConfig+".pid")
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("error class = %q", ErrorClassOf(err))
	}
	assertNestedTopologyGone(t, outerPID, resolverPID, grandchildPID)
	_ = manager.Close()
}

func assertNestedTopologyGone(t *testing.T, outerPID, resolverPID, grandchildPID int) {
	t.Helper()
	for label, pid := range map[string]int{
		"outer helper":   outerPID,
		"PIN resolver":   resolverPID,
		"resolver child": grandchildPID,
	} {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("%s process %d still exists after manager returned: %v", label, pid, err)
		}
	}
	if err := syscall.Kill(-outerPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("helper process group %d still exists after manager returned: %v", outerPID, err)
	}
}

func testHardwareManager(t *testing.T, action string, timeout time.Duration) *HardwareManager {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), hardwareManagerChildPrefix+action)
	manager := NewHardwareManager(executable, configPath, timeout)
	manager.environment = []string{
		"HOME=/home/test", "PATH=/usr/bin:/bin", "LC_ALL=C",
		"YUBITOUCH_PIN=must-not-cross", "PRIVATE_SECRET=must-not-cross",
	}
	return manager
}

func setHardwareProcessWaitGroup(process *hardwareProcess, wait func(int, time.Duration) bool) {
	process.mu.Lock()
	process.waitGroup = wait
	process.mu.Unlock()
}

func TestHardwareManagerFileKeyIsNotRetainedAfterWait(t *testing.T) {
	fixture := newHelperFixture(t)
	manager := testHardwareManager(t, "success", 10*time.Second)
	defer manager.Close()
	call, err := manager.Start(context.Background(), Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := call.Wait()
	if err != nil {
		t.Fatal(err)
	}
	call.mu.Lock()
	retained := append([]byte(nil), call.fileKey...)
	call.mu.Unlock()
	if len(retained) != 0 || !bytes.Equal(fileKey, []byte("runner-file-key!")) {
		ClearSecret(fileKey)
		t.Fatal("HardwareCall retained the consumed file key")
	}
	ClearSecret(fileKey)
}

func assertPIDGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d is still present", pid)
}
