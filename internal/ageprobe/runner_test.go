package ageprobe

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/agehardware"
)

const runnerChildPrefix = "ageprobe-runner-"
const parentDeathLauncherEnvironment = "YUBITOUCH_TEST_AGEPROBE_PARENT_DEATH_LAUNCHER"

func TestMain(m *testing.M) {
	if os.Getenv(internalModeEnvironment) == "1" {
		configPath := os.Getenv("YUBITOUCH_CONFIG")
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

	action := strings.TrimPrefix(filepath.Base(configPath), runnerChildPrefix)
	const targetSerial = "12345678"
	if action == "crash" {
		_, _ = io.WriteString(os.Stderr, "serial="+targetSerial+" op://private/reference")
		return 23
	}
	if action == "oversized" {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], maxResponseFrame+1)
		_, _ = os.Stdout.Write(header[:])
		return 0
	}
	if action == "env" {
		publicKey := testPublicKeyForChild()
		encodedPublic := base64.RawURLEncoding.EncodeToString(publicKey[:])
		for _, argument := range os.Args[1:] {
			if strings.Contains(argument, targetSerial) || strings.Contains(argument, encodedPublic) {
				return writeRunnerChildFailure(ErrorHelper)
			}
		}
		for _, entry := range os.Environ() {
			if strings.Contains(entry, targetSerial) || strings.Contains(entry, encodedPublic) {
				return writeRunnerChildFailure(ErrorHelper)
			}
		}
		for _, name := range []string{
			"YUBITOUCH_PIN", "YUBITOUCH_AGE_SERIAL", "YUBITOUCH_AGE_SLOT",
			"YUBITOUCH_AGE_RECOVERY_IDENTITY", "AGEDEBUG", "AGE_PLUGIN_PATH",
			"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_AUTH_SOCK", "GIT_ASKPASS",
			"DISPLAY", "PRIVATE_SECRET",
		} {
			if _, present := os.LookupEnv(name); present {
				return writeRunnerChildFailure(ErrorHelper)
			}
		}
		if os.Getenv("YUBITOUCH_CONFIG") != configPath || os.Getenv(parentWatchEnvironment) != "3" || os.Getenv("HOME") == "" {
			return writeRunnerChildFailure(ErrorHelper)
		}
	}

	encoded, err := readFrame(os.Stdin, maxRequestFrame)
	if err != nil || ensureEOF(os.Stdin) != nil {
		clear(encoded)
		return 24
	}
	request, err := unmarshalRequest(encoded)
	clear(encoded)
	if err != nil {
		return 25
	}

	if action == "hang" || action == "cancel" || action == "parent-death" {
		child := exec.Command("/bin/sleep", "60")
		child.Stdout = io.Discard
		child.Stderr = io.Discard
		if err := child.Start(); err != nil {
			return 26
		}
		_ = os.WriteFile(configPath+".pid", []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		for {
			time.Sleep(time.Second)
		}
	}
	if action == "classified" {
		return writeRunnerChildFailure(ErrorTargetMismatch)
	}

	publicKey := testPublicKeyForChild()
	var result response
	switch request.Operation {
	case OperationReadPublic:
		result.PublicKey = publicKey
	case OperationProbe:
		result.State = agehardware.Connected
	default:
		return 27
	}
	encodedResponse, err := marshalSuccess(request.Operation, result)
	if err != nil {
		return 28
	}
	defer clear(encodedResponse)
	if err := writeFrame(os.Stdout, encodedResponse, maxResponseFrame); err != nil {
		return 29
	}
	if action == "trailing" {
		_, _ = io.WriteString(os.Stdout, "x")
	}
	if action == "valid-nonzero" {
		return 31
	}
	return 0
}

func writeRunnerChildFailure(class ErrorClass) int {
	encoded := marshalFailure(class)
	defer clear(encoded)
	if err := writeFrame(os.Stdout, encoded, maxResponseFrame); err != nil {
		return 30
	}
	return helperFailureCode
}

func TestRunnerReadPublicAndProbe(t *testing.T) {
	publicKey := testPublicKey(t)
	for _, action := range []string{"success", "env"} {
		t.Run(action, func(t *testing.T) {
			runner := testRunner(t, action, 10*time.Second)
			runner.environment = []string{
				"HOME=/home/test", "PATH=/usr/bin:/bin", "LC_ALL=C",
				"YUBITOUCH_PIN=123456", "YUBITOUCH_AGE_SERIAL=private",
				"YUBITOUCH_AGE_SLOT=private", "YUBITOUCH_AGE_RECOVERY_IDENTITY=private",
				"AGEDEBUG=plugin", "AGE_PLUGIN_PATH=/private/plugin",
				"SSH_ASKPASS=/private/askpass", "SSH_ASKPASS_REQUIRE=force",
				"SSH_AUTH_SOCK=/private/agent", "GIT_ASKPASS=/private/git-askpass",
				"DISPLAY=private", "PRIVATE_SECRET=do-not-inherit",
			}
			got, err := runner.ReadPublic(context.Background(), "12345678", "82")
			if err != nil {
				t.Fatal(err)
			}
			if got != publicKey {
				t.Fatal("runner returned an unexpected public key")
			}
			probe, err := runner.Probe(context.Background(), agehardware.Target{
				Serial: "12345678", Slot: "82", PublicKey: publicKey,
			})
			if err != nil || probe.State != agehardware.Connected {
				t.Fatalf("probe=%+v err=%v", probe, err)
			}
		})
	}
}

func TestRunnerTimeoutKillsAndWaitsForProcessGroup(t *testing.T) {
	runner := testRunner(t, "hang", 2*time.Second)
	started := time.Now()
	_, err := runner.ReadPublic(context.Background(), "12345678", "82")
	if ErrorClassOf(err) != ErrorTimeout {
		t.Fatalf("class=%q, want %q", ErrorClassOf(err), ErrorTimeout)
	}
	if elapsed := time.Since(started); elapsed > 8*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestRunnerCancellationKillsAndWaitsForProcessGroup(t *testing.T) {
	runner := testRunner(t, "cancel", 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := runner.ReadPublic(ctx, "12345678", "82")
		result <- err
	}()
	_ = waitForPIDFile(t, runner.configPath+".pid")
	cancel()
	if err := <-result; ErrorClassOf(err) != ErrorCanceled {
		t.Fatalf("class=%q, want %q", ErrorClassOf(err), ErrorCanceled)
	}
	assertChildGone(t, runner.configPath+".pid")
}

func TestHelperAndGrandchildExitWhenLauncherIsKilled(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), runnerChildPrefix+"parent-death")
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

	grandchildPID := waitForPIDFile(t, configPath+".pid")
	helperPID, err := syscall.Getpgid(grandchildPID)
	if err != nil || helperPID <= 1 {
		t.Fatalf("resolve helper process group: %v; launcher diagnostics: %s", err, launcherStderr.String())
	}
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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(executable, configPath, time.Minute)
	publicKey, err := runner.ReadPublic(context.Background(), "12345678", "82")
	clear(publicKey[:])
	t.Fatalf("helper exited before launcher was killed: %v", err)
}

func TestRunnerCollapsesOutputCrashAndExitFailures(t *testing.T) {
	for _, action := range []string{"crash", "oversized", "trailing", "valid-nonzero"} {
		t.Run(action, func(t *testing.T) {
			runner := testRunner(t, action, 10*time.Second)
			_, err := runner.ReadPublic(context.Background(), "12345678", "82")
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("class=%q, want %q", ErrorClassOf(err), ErrorHelper)
			}
			if strings.Contains(err.Error(), "12345678") || strings.Contains(err.Error(), "op://") {
				t.Fatal("runner exposed child stderr")
			}
		})
	}
}

func TestRunnerPreservesPredefinedFailureClass(t *testing.T) {
	runner := testRunner(t, "classified", 10*time.Second)
	result, err := runner.Probe(context.Background(), agehardware.Target{
		Serial: "12345678", Slot: "82", PublicKey: testPublicKey(t),
	})
	if ErrorClassOf(err) != ErrorTargetMismatch || result.State != agehardware.Mismatch || !errors.Is(err, agehardware.ErrTargetMismatch) {
		t.Fatalf("result=%+v class=%q err=%v", result, ErrorClassOf(err), err)
	}
}

func TestRunnerSuccessAfterFailureAndCancelAfterWait(t *testing.T) {
	runner := testRunner(t, "classified", 10*time.Second)
	_, err := runner.ReadPublic(context.Background(), "12345678", "82")
	if ErrorClassOf(err) != ErrorTargetMismatch {
		t.Fatalf("first class=%q, want %q", ErrorClassOf(err), ErrorTargetMismatch)
	}

	runner.configPath = filepath.Join(t.TempDir(), runnerChildPrefix+"success")
	ctx, cancel := context.WithCancel(context.Background())
	publicKey, err := runner.ReadPublic(ctx, "12345678", "82")
	if err != nil || publicKey != testPublicKey(t) {
		t.Fatalf("success after failure public key mismatch: %v", err)
	}
	cancel()

	result, err := runner.Probe(context.Background(), agehardware.Target{
		Serial: "12345678", Slot: "82", PublicKey: testPublicKey(t),
	})
	if err != nil || result.State != agehardware.Connected {
		t.Fatalf("probe after cancel-after-wait result=%+v err=%v", result, err)
	}
}

func TestRunnerSupportsConcurrentOneShotCalls(t *testing.T) {
	runner := testRunner(t, "success", 10*time.Second)
	publicKey := testPublicKey(t)
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := runner.Probe(context.Background(), agehardware.Target{
				Serial: "12345678", Slot: "82", PublicKey: publicKey,
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			if result.State != agehardware.Connected {
				errorsSeen <- errors.New("unexpected probe state")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
}

func TestSanitizedEnvironmentUsesAllowlist(t *testing.T) {
	environment := sanitizedEnvironment([]string{
		"HOME=/home/test", "LC_CTYPE=UTF-8", "YUBITOUCH_PIN=123456", "YUBITOUCH_AGE_SERIAL=12345678",
		"AGEDEBUG=plugin", "SSH_ASKPASS=/secret", "DISPLAY=secret", "PRIVATE_SECRET=value", "HOME=/other",
	}, "/private/config.json")
	joined := strings.Join(environment, "\n")
	for _, forbidden := range []string{"123456", "12345678", "AGEDEBUG", "SSH_ASKPASS", "DISPLAY", "PRIVATE_SECRET", "/other"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sanitized environment retained %q", forbidden)
		}
	}
	for _, required := range []string{
		"HOME=/home/test", "LC_CTYPE=UTF-8", internalModeEnvironment + "=1",
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
	t.Fatalf("timed out waiting for helper child PID")
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
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s process %d is still alive; launcher diagnostics: %s", label, pid, diagnostics)
}

func testPublicKeyForChild() [32]byte {
	scalar := bytes.Repeat([]byte{0x42}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(scalar)
	clear(scalar)
	if err != nil {
		return [32]byte{}
	}
	var publicKey [32]byte
	copy(publicKey[:], privateKey.PublicKey().Bytes())
	return publicKey
}
