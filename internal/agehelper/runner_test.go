package agehelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/ageprofile"
)

const runnerChildPrefix = "runner-child-"
const parentAuthChildPrefix = "parent-auth-child-"
const parentDeathLauncherEnvironment = "YUBITOUCH_TEST_AGE_PARENT_DEATH_LAUNCHER"

func TestMain(m *testing.M) {
	if _, valid := parseMode(os.Getenv(internalModeEnvironment)); valid {
		configPath := os.Getenv("YUBITOUCH_CONFIG")
		if strings.HasPrefix(filepath.Base(configPath), parentAuthChildPrefix) {
			home, _ := os.UserHomeDir()
			handled, code := RunInternalFromEnvironment(context.Background(), os.Stdin, os.Stdout, os.Getenv, home)
			if !handled {
				os.Exit(31)
			}
			os.Exit(code)
		}
		if strings.HasPrefix(filepath.Base(configPath), runnerChildPrefix) {
			os.Exit(runRunnerTestChild(configPath))
		}
	}
	os.Exit(m.Run())
}

func runRunnerTestChild(configPath string) int {
	stopParentWatch, err := startParentLifetimeWatch(os.Getenv)
	if err != nil {
		return 32
	}
	defer stopParentWatch()
	mode, valid := parseMode(os.Getenv(internalModeEnvironment))
	if !valid {
		return 33
	}
	var continueReader io.ReadCloser
	if mode == ModeHardware {
		continueReader, err = openHardwareContinue(os.Getenv)
		if err != nil {
			return 34
		}
		defer continueReader.Close()
	} else if os.Getenv(hardwareContinueEnvironment) != "" {
		return 35
	}

	action := strings.TrimPrefix(filepath.Base(configPath), runnerChildPrefix)
	if action == "crash" {
		_, _ = io.WriteString(os.Stderr, "private PIN and recovery identity must be discarded")
		return 23
	}
	if action == "oversized" {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], maxResponseFrame+1)
		_, _ = os.Stdout.Write(header[:])
		return 0
	}

	request, err := readFrame(os.Stdin, maxRequestFrame)
	if err != nil || ensureEOF(os.Stdin) != nil {
		return 24
	}
	clear(request)

	if action == "hang" || action == "cancel" || action == "parent-death" {
		return hangRunnerTestChild(configPath)
	}
	if action == "pin-failure" {
		return writeRunnerChildError(ErrorPINProvider)
	}
	if action == "recovery-ready" {
		if mode != ModeRecovery || writeRunnerReady() != nil {
			return 36
		}
		return 0
	}
	if action == "malformed-ready" {
		if err := writeFrame(os.Stdout, []byte(`{"version":2,"type":"ready_for_touch","extra":true}`), maxResponseFrame); err != nil {
			return 37
		}
		return 0
	}
	if action == "env" {
		for _, name := range []string{
			"YUBITOUCH_PIN", "YUBITOUCH_AGE_SERIAL", "AGEDEBUG", "AGE_PLUGIN_PATH",
			"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_AUTH_SOCK", "GIT_ASKPASS", "DISPLAY", "PRIVATE_SECRET",
		} {
			if _, present := os.LookupEnv(name); present {
				return writeRunnerChildError(ErrorHelper)
			}
		}
		continueDescriptor := os.Getenv(hardwareContinueEnvironment)
		if os.Getenv(internalModeEnvironment) == "" || os.Getenv("YUBITOUCH_CONFIG") != configPath ||
			os.Getenv(parentWatchEnvironment) != "3" || os.Getenv("HOME") == "" ||
			(mode == ModeHardware && continueDescriptor != "4") || (mode == ModeRecovery && continueDescriptor != "") {
			return writeRunnerChildError(ErrorHelper)
		}
	}
	if action == "error-then-ready" {
		encoded, err := marshalResponse(nil, ErrorPINProvider)
		if err != nil {
			return 38
		}
		if err := writeFrame(os.Stdout, encoded, maxResponseFrame); err != nil {
			clear(encoded)
			return 39
		}
		clear(encoded)
		if err := writeRunnerReady(); err != nil {
			return 40
		}
		return helperFailureExitCode
	}
	if mode == ModeHardware && action != "missing-ready" {
		if err := writeRunnerReady(); err != nil {
			return 41
		}
		if action == "duplicate-ready" {
			if err := writeRunnerReady(); err != nil {
				return 42
			}
		}
		if err := readHardwareContinue(continueReader); err != nil {
			return writeRunnerChildError(ErrorHelper)
		}
		if action == "ready-hang" {
			return hangRunnerTestChild(configPath)
		}
	}

	encoded, err := marshalResponse([]byte("runner-file-key!"), "")
	if err != nil {
		return 26
	}
	defer clear(encoded)
	if err := writeFrame(os.Stdout, encoded, maxResponseFrame); err != nil {
		return 27
	}
	if action == "valid-nonzero" {
		return 30
	}
	if action == "trailing" {
		_, _ = io.WriteString(os.Stdout, "x")
	}
	return 0
}

func writeRunnerReady() error {
	ready, err := marshalReady()
	if err != nil {
		return err
	}
	defer clear(ready)
	return writeFrame(os.Stdout, ready, maxResponseFrame)
}

func hangRunnerTestChild(configPath string) int {
	child := exec.Command("/bin/sleep", "60")
	child.Stdout = io.Discard
	child.Stderr = io.Discard
	if err := child.Start(); err != nil {
		return 25
	}
	_ = os.WriteFile(configPath+".pid", []byte(strconv.Itoa(child.Process.Pid)), 0o600)
	for {
		time.Sleep(time.Second)
	}
}

func writeRunnerChildError(class ErrorClass) int {
	encoded, err := marshalResponse(nil, class)
	if err != nil {
		return 28
	}
	defer clear(encoded)
	if err := writeFrame(os.Stdout, encoded, maxResponseFrame); err != nil {
		return 29
	}
	return helperFailureExitCode
}

func TestRunnerSuccessAndEnvironmentSanitization(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, action := range []string{"success", "env"} {
		t.Run(action, func(t *testing.T) {
			runner := testRunner(t, action, 10*time.Second)
			runner.environment = []string{
				"HOME=/home/test", "PATH=/usr/bin:/bin", "LC_ALL=C",
				"YUBITOUCH_PIN=123456", "YUBITOUCH_AGE_SERIAL=private",
				"AGEDEBUG=plugin", "AGE_PLUGIN_PATH=/private/plugin",
				"SSH_ASKPASS=/private/askpass", "SSH_ASKPASS_REQUIRE=force",
				"SSH_AUTH_SOCK=/private/agent", "GIT_ASKPASS=/private/git-askpass",
				"DISPLAY=private", "PRIVATE_SECRET=do-not-inherit",
			}
			fileKey, err := runner.Run(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
			if err != nil {
				t.Fatal(err)
			}
			defer ClearSecret(fileKey)
			if string(fileKey) != "runner-file-key!" {
				t.Fatal("runner returned an unexpected file key")
			}
		})
	}
}

func TestRunnerHardwareTwoStageAPI(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "success", 10*time.Second)
	call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := call.WaitReady(); err != nil {
		t.Fatal(err)
	}
	if call.cmd.ProcessState != nil {
		t.Fatal("helper exited before the continue signal")
	}
	if err := call.WaitReady(); err != nil {
		t.Fatalf("repeated WaitReady failed: %v", err)
	}
	fileKey, err := call.ContinueAndWait()
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSecret(fileKey)
	if string(fileKey) != "runner-file-key!" {
		t.Fatal("runner returned an unexpected file key")
	}
	if call.cmd.ProcessState == nil || !call.cmd.ProcessState.Exited() {
		t.Fatal("helper was not reaped after its terminal response")
	}
}

func TestRunnerWaitReadyReturnsEarlyFailureAfterReaping(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "pin-failure", 10*time.Second)
	call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorPINProvider {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorPINProvider)
	}
	if call.cmd.ProcessState == nil || !call.cmd.ProcessState.Exited() {
		t.Fatal("WaitReady returned before the failed helper was reaped")
	}
	if _, err := call.ContinueAndWait(); ErrorClassOf(err) != ErrorPINProvider {
		t.Fatalf("repeated error class = %q, want %q", ErrorClassOf(err), ErrorPINProvider)
	}
}

func TestRunnerRejectsInvalidReadySequences(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, action := range []string{"malformed-ready", "missing-ready", "error-then-ready"} {
		t.Run(action, func(t *testing.T) {
			runner := testRunner(t, action, 10*time.Second)
			call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
			if err != nil {
				t.Fatal(err)
			}
			if err := call.WaitReady(); ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorHelper)
			}
			if call.cmd.ProcessState == nil || !call.cmd.ProcessState.Exited() {
				t.Fatal("protocol failure returned before the helper was reaped")
			}
		})
	}

	t.Run("duplicate-ready", func(t *testing.T) {
		runner := testRunner(t, "duplicate-ready", 10*time.Second)
		call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
		if err != nil {
			t.Fatal(err)
		}
		if err := call.WaitReady(); err != nil {
			t.Fatal(err)
		}
		if _, err := call.ContinueAndWait(); ErrorClassOf(err) != ErrorHelper {
			t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorHelper)
		}
	})

	t.Run("recovery-ready", func(t *testing.T) {
		runner := testRunner(t, "recovery-ready", 10*time.Second)
		if _, err := runner.Run(context.Background(), ModeRecovery, Request{Envelope: fixture.recoveryEnvelope}); ErrorClassOf(err) != ErrorHelper {
			t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorHelper)
		}
	})
}

func TestRunnerUsesModeSpecificDescriptorsAndEnvironment(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, test := range []struct {
		name       string
		mode       Mode
		envelope   ageprofile.Envelope
		extraFiles int
		continueFD bool
	}{
		{"hardware", ModeHardware, fixture.hardwareEnvelope, 2, true},
		{"recovery", ModeRecovery, fixture.recoveryEnvelope, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := testRunner(t, "env", 10*time.Second)
			var command *exec.Cmd
			runner.command = func(path string) *exec.Cmd {
				command = exec.Command(path)
				return command
			}
			fileKey, err := runner.Run(context.Background(), test.mode, Request{Envelope: test.envelope})
			if err != nil {
				t.Fatal(err)
			}
			ClearSecret(fileKey)
			if command == nil || len(command.ExtraFiles) != test.extraFiles {
				t.Fatalf("extra files = %d, want %d", len(command.ExtraFiles), test.extraFiles)
			}
			continueEntry := hardwareContinueEnvironment + "=4"
			found := false
			for _, entry := range command.Env {
				if entry == continueEntry {
					found = true
				}
			}
			if found != test.continueFD {
				t.Fatalf("continue environment present = %t, want %t", found, test.continueFD)
			}
		})
	}
}

func TestInternalHelperRejectsNonHardenedSameExecutableParent(t *testing.T) {
	fixture := newHelperFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), parentAuthChildPrefix+"valid")
	runner := NewRunner(executable, configPath, 10*time.Second)
	fileKey, err := runner.Run(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	ClearSecret(fileKey)
	if ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorHelper)
	}
}

func TestInternalHelperRejectsShellParent(t *testing.T) {
	fixture := newHelperFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), parentAuthChildPrefix+"shell")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	cmd := exec.Command("/bin/sh", "-c", `"$1" & child=$!; wait "$child"`, "sh", executable)
	cmd.Env = []string{
		"HOME=" + home,
		internalModeEnvironment + "=" + string(ModeHardware),
		"YUBITOUCH_CONFIG=" + configPath,
	}
	cmd.Stdin = &input
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		t.Fatal("unauthorized helper unexpectedly exited successfully")
	}
	if class := responseErrorClass(t, &output); class != ErrorHelper {
		t.Fatalf("error class = %q, want %q", class, ErrorHelper)
	}
}

func TestRunnerTimeoutKillsAndWaitsForProcessGroup(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "hang", 200*time.Millisecond)
	started := time.Now()
	_, err := runner.Run(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if ErrorClassOf(err) != ErrorTimeout {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorTimeout)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestRunnerContextCancelBeforeReadyKillsAndReaps(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "hang", 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	call, err := runner.Start(ctx, ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForPIDFile(t, runner.configPath+".pid")
	cancel()
	if err := call.WaitReady(); ErrorClassOf(err) != ErrorCanceled {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorCanceled)
	}
	if call.cmd.ProcessState == nil {
		t.Fatal("canceled helper was not reaped before WaitReady returned")
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestRunnerCancelBetweenReadyAndContinue(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "success", 10*time.Second)
	call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := call.WaitReady(); err != nil {
		t.Fatal(err)
	}
	call.Cancel()
	if _, err := call.ContinueAndWait(); ErrorClassOf(err) != ErrorCanceled {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorCanceled)
	}
	if call.cmd.ProcessState == nil {
		t.Fatal("canceled helper was not reaped")
	}
}

func TestRunnerTimeoutAfterContinueKillsProcessGroup(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "ready-hang", 300*time.Millisecond)
	call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := call.WaitReady(); err != nil {
		t.Fatal(err)
	}
	if _, err := call.ContinueAndWait(); ErrorClassOf(err) != ErrorTimeout {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorTimeout)
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestRunnerCancelAfterContinueKillsProcessGroup(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "ready-hang", 10*time.Second)
	call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := call.WaitReady(); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := call.ContinueAndWait()
		result <- err
	}()
	_ = waitForPIDFile(t, runner.configPath+".pid")
	call.Cancel()
	if err := <-result; ErrorClassOf(err) != ErrorCanceled {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorCanceled)
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestRunnerConcurrentReadyContinueAndCancel(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "ready-hang", 10*time.Second)
	call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := call.WaitReady(); err != nil {
		t.Fatal(err)
	}

	type waitResult struct {
		continued bool
		err       error
	}
	const workers = 12
	results := make(chan waitResult, workers)
	for index := 0; index < workers; index++ {
		continued := index%2 == 0
		go func() {
			if continued {
				_, err := call.ContinueAndWait()
				results <- waitResult{continued: true, err: err}
				return
			}
			results <- waitResult{err: call.WaitReady()}
		}()
	}
	_ = waitForPIDFile(t, runner.configPath+".pid")
	call.Cancel()
	for index := 0; index < workers; index++ {
		result := <-results
		if result.continued && ErrorClassOf(result.err) != ErrorCanceled {
			t.Fatalf("continue error class = %q, want %q", ErrorClassOf(result.err), ErrorCanceled)
		}
		if !result.continued && result.err != nil {
			t.Fatalf("WaitReady failed: %v", result.err)
		}
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestContinueWriteFailureCannotReturnSuccess(t *testing.T) {
	readyDone := make(chan struct{})
	close(readyDone)
	done := make(chan struct{})
	close(done)
	fileKey := []byte("runner-file-key!")
	call := &Call{
		mode:           ModeHardware,
		stdin:          failingWriteCloser{},
		stdout:         io.NopCloser(bytes.NewReader(nil)),
		continueWriter: failingWriteCloser{},
		readyDone:      readyDone,
		done:           done,
		fileKey:        fileKey,
	}
	got, err := call.ContinueAndWait()
	if got != nil || ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("file key = %v, error class = %q", got, ErrorClassOf(err))
	}
	if !bytes.Equal(fileKey, make([]byte, len(fileKey))) {
		t.Fatal("file key was not cleared after continue failed")
	}
}

func TestRunnerCancelCurrentKillsAndWaits(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "cancel", 5*time.Second)
	result := make(chan error, 1)
	go func() {
		_, err := runner.Run(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
		result <- err
	}()
	_ = waitForPIDFile(t, runner.configPath+".pid")
	runner.CancelCurrent()
	if err := <-result; ErrorClassOf(err) != ErrorCanceled {
		t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorCanceled)
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestHelperAndGrandchildExitWhenLauncherIsKilled(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), runnerChildPrefix+"parent-death")
	encoded, err := marshalRequest(Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if err := os.WriteFile(configPath+".request", encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcher := exec.Command(executable, "-test.run=^TestParentDeathLauncherProcess$")
	launcher.Env = append(os.Environ(), parentDeathLauncherEnvironment+"="+configPath)
	launcher.Stdout = io.Discard
	var launcherStderr bytes.Buffer
	launcher.Stderr = &launcherStderr
	if err := launcher.Start(); err != nil {
		t.Fatal(err)
	}
	launcherDone := false
	defer func() {
		if !launcherDone {
			_ = launcher.Process.Kill()
			_ = launcher.Wait()
		}
	}()

	helperPID := waitForPIDFile(t, configPath+".helper-pid")
	grandchildPID := waitForPIDFile(t, configPath+".pid")
	if err := launcher.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := launcher.Wait(); err == nil {
		t.Fatal("launcher unexpectedly exited successfully")
	}
	launcherDone = true

	assertProcessGone(t, helperPID, "helper", launcherStderr.String())
	assertProcessGone(t, grandchildPID, "grandchild", launcherStderr.String())
}

// TestParentDeathLauncherProcess is run only in a subprocess. Killing this
// middle process exercises kernel closure of Runner's parent-lifetime pipe.
func TestParentDeathLauncherProcess(t *testing.T) {
	configPath := os.Getenv(parentDeathLauncherEnvironment)
	if configPath == "" {
		t.Skip("parent-death launcher subprocess only")
	}
	encoded, err := os.ReadFile(configPath + ".request")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	request, err := unmarshalRequest(encoded, ModeHardware)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(executable, configPath, time.Minute)
	call, err := runner.Start(context.Background(), ModeHardware, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath+".helper-pid", []byte(strconv.Itoa(call.cmd.Process.Pid)), 0o600); err != nil {
		call.Cancel()
		t.Fatal(err)
	}
	fileKey, err := call.Wait()
	ClearSecret(fileKey)
	t.Fatalf("helper exited before launcher was killed: %v", err)
}

func TestRunnerCancelBeforeStartPreventsLaunch(t *testing.T) {
	fixture := newHelperFixture(t)
	runner := testRunner(t, "success", time.Second)
	launches := 0
	runner.command = func(path string) *exec.Cmd {
		launches++
		return exec.Command(path)
	}
	runner.CancelCurrent()
	_, err := runner.Run(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
	if ErrorClassOf(err) != ErrorCanceled || launches != 0 {
		t.Fatalf("error class = %q, launches = %d", ErrorClassOf(err), launches)
	}
}

func TestRunnerCancelAfterWaitIsIdempotent(t *testing.T) {
	fixture := newHelperFixture(t)
	for i := 0; i < 10; i++ {
		runner := testRunner(t, "success", 10*time.Second)
		call, err := runner.Start(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
		if err != nil {
			t.Fatal(err)
		}
		fileKey, err := call.Wait()
		if err != nil {
			t.Fatal(err)
		}
		ClearSecret(fileKey)
		call.Cancel()
		runner.CancelCurrent()
	}
}

func TestRunnerCollapsesCrashAndMalformedOutput(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, action := range []string{"crash", "oversized", "trailing", "valid-nonzero"} {
		t.Run(action, func(t *testing.T) {
			runner := testRunner(t, action, 10*time.Second)
			_, err := runner.Run(context.Background(), ModeHardware, Request{Envelope: fixture.hardwareEnvelope})
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorHelper)
			}
			if strings.Contains(err.Error(), "private PIN") || strings.Contains(err.Error(), "recovery identity") {
				t.Fatal("runner error included child stderr")
			}
		})
	}
}

func TestSanitizedEnvironmentUsesAllowlist(t *testing.T) {
	environment := sanitizedEnvironment([]string{
		"HOME=/home/test", "LC_CTYPE=UTF-8", "YUBITOUCH_PIN=123456", "AGEDEBUG=plugin",
		"SSH_ASKPASS=/secret", "DISPLAY=secret", "PRIVATE_SECRET=value", "HOME=/other",
	}, "/private/config.json", ModeRecovery)
	joined := strings.Join(environment, "\n")
	for _, forbidden := range []string{"123456", "AGEDEBUG", "SSH_ASKPASS", "DISPLAY", "PRIVATE_SECRET", "/other"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sanitized environment retained %q", forbidden)
		}
	}
	for _, required := range []string{
		"HOME=/home/test", "LC_CTYPE=UTF-8", internalModeEnvironment + "=recovery",
		"YUBITOUCH_CONFIG=/private/config.json", parentWatchEnvironment + "=3",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("sanitized environment omitted %q", required)
		}
	}
}

func testRunner(t *testing.T, action string, timeout time.Duration) *Runner {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), runnerChildPrefix+action)
	return NewRunner(executable, configPath, timeout)
}

func waitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if parseErr == nil && pid > 1 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
	return 0
}

func assertChildGone(t *testing.T, path string) {
	t.Helper()
	pid := readPIDFile(t, path)
	assertProcessGone(t, pid, "grandchild", "")
}

func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid process ID in %s", path)
	}
	return pid
}

func assertProcessGone(t *testing.T, pid int, label, diagnostics string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s process %d is still alive; launcher diagnostics: %s", label, pid, diagnostics)
}

type failingWriteCloser struct{}

func (failingWriteCloser) Write([]byte) (int, error) {
	return 0, errors.New("continue writer failed")
}

func (failingWriteCloser) Close() error { return nil }

func TestClassErrorFormattingIsFixed(t *testing.T) {
	for _, class := range []ErrorClass{ErrorInvalidRequest, ErrorConfiguration, ErrorHardware, ErrorRecoveryUnavailable, ErrorHelper} {
		message := (&ClassError{Class: class}).Error()
		if strings.Contains(message, "%!") || strings.Contains(message, fmt.Sprint(os.Environ())) {
			t.Fatalf("unsafe class error message %q", message)
		}
	}
}
