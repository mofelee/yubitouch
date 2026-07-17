package backend

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/system"
)

func TestManagerStartsConnectsAndStopsAgent(t *testing.T) {
	sshAgent, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent is not installed")
	}
	dir, err := os.MkdirTemp("/tmp", "yt-backend-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := config.Config{BackendSocketPath: filepath.Join(dir, "backend.sock")}
	manager := New(cfg, system.Dependencies{SSHAgent: sshAgent}, "/bin/false", filepath.Join(dir, "config.json"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.EnsureAgent(ctx); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	backend, err := manager.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := backend.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("fresh backend listed %d keys, want 0", len(keys))
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := manager.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.BackendSocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backend socket still exists: %v", err)
	}
}

func TestAgentArgumentsAllowOnlyConfiguredYKCS11Provider(t *testing.T) {
	manager := New(
		config.Config{BackendSocketPath: "/tmp/yubitouch-backend.sock"},
		system.Dependencies{YKCS11: "/opt/homebrew/Cellar/yubico-piv-tool/2.7.3/lib/libykcs11.2.7.3.dylib"},
		"/bin/false",
		"/tmp/yubitouch-config.json",
	)
	want := []string{
		"-D",
		"-a", "/tmp/yubitouch-backend.sock",
		"-P", "/opt/homebrew/Cellar/yubico-piv-tool/2.7.3/lib/libykcs11.2.7.3.dylib",
	}
	got := manager.agentArguments()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("agent arguments = %q, want %q", got, want)
	}
}

func TestAgentArgumentsOmitEmptyProviderAllowlist(t *testing.T) {
	manager := New(
		config.Config{BackendSocketPath: "/tmp/yubitouch-backend.sock"},
		system.Dependencies{},
		"/bin/false",
		"/tmp/yubitouch-config.json",
	)
	want := []string{"-D", "-a", "/tmp/yubitouch-backend.sock"}
	got := manager.agentArguments()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("agent arguments = %q, want %q", got, want)
	}
}

func TestManagerRestartsCrashedAgentAndMissingSocket(t *testing.T) {
	sshAgent, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent is not installed")
	}
	dir, err := os.MkdirTemp("/tmp", "yt-backend-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := config.Config{BackendSocketPath: filepath.Join(dir, "backend.sock")}
	manager := New(cfg, system.Dependencies{SSHAgent: sshAgent}, "/bin/false", filepath.Join(dir, "config.json"))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := manager.EnsureAgent(ctx); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	firstPID := manager.cmd.Process.Pid
	if err := manager.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitForSocketState(t, cfg.BackendSocketPath, false)
	if err := manager.EnsureAgent(ctx); err != nil {
		t.Fatalf("restart crashed agent: %v", err)
	}
	secondPID := manager.cmd.Process.Pid
	if secondPID == firstPID {
		t.Fatalf("agent PID did not change after crash: %d", firstPID)
	}

	if err := os.Remove(cfg.BackendSocketPath); err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureAgent(ctx); err != nil {
		t.Fatalf("recover missing socket: %v", err)
	}
	thirdPID := manager.cmd.Process.Pid
	if thirdPID == secondPID || !socketReachable(cfg.BackendSocketPath) {
		t.Fatalf("missing socket was not recovered: second=%d third=%d", secondPID, thirdPID)
	}
}

func TestNewManagerDoesNotTakeOverReachableAgent(t *testing.T) {
	sshAgent, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent is not installed")
	}
	dir, err := os.MkdirTemp("/tmp", "yt-backend-ownership-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := config.Config{BackendSocketPath: filepath.Join(dir, "backend.sock")}
	deps := system.Dependencies{SSHAgent: sshAgent}
	owner := New(cfg, deps, "/bin/false", filepath.Join(dir, "config.json"))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = owner.Stop(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.EnsureAgent(ctx); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	ownerPID := owner.cmd.Process.Pid

	restartedDaemon := New(cfg, deps, "/bin/false", filepath.Join(dir, "config.json"))
	err = restartedDaemon.EnsureAgent(ctx)
	if err == nil || !strings.Contains(err.Error(), "unmanaged agent is already listening") {
		t.Fatalf("new manager error = %v, want unmanaged agent refusal", err)
	}
	if owner.cmd.Process.Pid != ownerPID || !socketReachable(cfg.BackendSocketPath) {
		t.Fatalf("owner agent was disturbed: pid=%d want=%d reachable=%v",
			owner.cmd.Process.Pid, ownerPID, socketReachable(cfg.BackendSocketPath))
	}
}

func TestLoadProviderCancellationStopsAskPassProcessGroup(t *testing.T) {
	dir := t.TempDir()
	provider := filepath.Join(dir, "libykcs11.dylib")
	if err := os.WriteFile(provider, []byte("test provider"), 0o644); err != nil {
		t.Fatal(err)
	}
	sshAdd := filepath.Join(dir, "ssh-add")
	script := "#!/bin/sh\n" +
		"sleep 30 &\n" +
		"child=$!\n" +
		"printf '%s\\n' \"$child\" > \"$YUBITOUCH_TEST_CHILD_PID\"\n" +
		"wait \"$child\"\n"
	if err := os.WriteFile(sshAdd, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	childPIDPath := filepath.Join(dir, "child.pid")
	cfg := config.Config{
		YKCS11Path:        provider,
		BackendSocketPath: filepath.Join(dir, "backend.sock"),
	}
	manager := New(cfg, system.Dependencies{SSHAdd: sshAdd}, "/bin/false", filepath.Join(dir, "config.json"))
	manager.processEnv = []string{
		"PATH=/usr/bin:/bin",
		"YUBITOUCH_TEST_CHILD_PID=" + childPIDPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := manager.loadProvider(ctx); err == nil {
		t.Fatal("loadProvider succeeded after its context expired")
	}
	data, err := os.ReadFile(childPIDPath)
	if err != nil {
		t.Fatal(err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	deadline := time.Now().Add(3 * time.Second)
	for processRunning(childPID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processRunning(childPID) {
		t.Fatalf("AskPass child process %d survived provider cancellation", childPID)
	}
}

func processRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func waitForSocketState(t *testing.T, path string, reachable bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for socketReachable(path) != reachable {
		if time.Now().After(deadline) {
			t.Fatalf("socket reachable=%v, want %v", socketReachable(path), reachable)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSanitizedEnvironment(t *testing.T) {
	got := sanitizedEnvironment([]string{
		"PATH=/bin",
		"SSH_AUTH_SOCK=/tmp/foreign.sock",
		"YUBITOUCH_INTERNAL_ASKPASS=1",
		"YUBITOUCH_PUBLIC_KEY=/tmp/key.pub",
	})
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "SSH_AUTH_SOCK") || strings.Contains(joined, "INTERNAL_ASKPASS") {
		t.Fatalf("unsafe environment survived: %v", got)
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "YUBITOUCH_PUBLIC_KEY") {
		t.Fatalf("expected environment was removed: %v", got)
	}
}
