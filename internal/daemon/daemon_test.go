package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/internal/state"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const daemonHelperEnvironment = "YUBITOUCH_DAEMON_TEST_HELPER"

type headlessApplication struct{}

func (headlessApplication) Handle(signing.Event) {}

func (headlessApplication) Run(ctx context.Context, serverResult <-chan error) error {
	select {
	case err := <-serverResult:
		return err
	case <-ctx.Done():
		return nil
	}
}

func TestDaemonProcessHelper(t *testing.T) {
	if os.Getenv(daemonHelperEnvironment) != "1" {
		return
	}
	err := Run(context.Background(), Options{
		ConfigPath:  os.Getenv("YUBITOUCH_DAEMON_TEST_CONFIG"),
		Home:        os.Getenv("YUBITOUCH_DAEMON_TEST_HOME"),
		Executable:  "/bin/false",
		Application: headlessApplication{},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDaemonRecoversPublicSocketAfterCrash(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-daemon-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	configPath, cfg := writeDaemonTestConfig(t, dir)

	first := startDaemonHelper(t, dir, configPath)
	t.Cleanup(func() { first.killAndWait(t) })
	waitForDaemonSocket(t, cfg.SocketPath, first)
	assertPublicIdentityWithoutBackend(t, cfg)
	firstPID := first.cmd.Process.Pid
	assertDaemonStatePID(t, configPath, firstPID)
	first.killAndWait(t)

	if info, err := os.Lstat(cfg.SocketPath); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("crash did not leave a stale public socket: info=%v err=%v", info, err)
	}
	assertDaemonStatePID(t, configPath, firstPID)

	second := startDaemonHelper(t, dir, configPath)
	t.Cleanup(func() { second.killAndWait(t) })
	waitForDaemonSocket(t, cfg.SocketPath, second)
	assertPublicIdentityWithoutBackend(t, cfg)
	secondPID := second.cmd.Process.Pid
	if secondPID == firstPID {
		t.Fatalf("daemon PID was reused: %d", secondPID)
	}
	assertDaemonStatePID(t, configPath, secondPID)
}

type daemonHelper struct {
	cmd     *exec.Cmd
	output  bytes.Buffer
	done    chan error
	waitErr error
	waited  bool
}

func startDaemonHelper(t *testing.T, home string, configPath string) *daemonHelper {
	t.Helper()
	helper := &daemonHelper{}
	helper.cmd = exec.Command(os.Args[0], "-test.run=^TestDaemonProcessHelper$")
	helper.cmd.Env = append(os.Environ(),
		daemonHelperEnvironment+"=1",
		"YUBITOUCH_DAEMON_TEST_CONFIG="+configPath,
		"YUBITOUCH_DAEMON_TEST_HOME="+home,
	)
	helper.cmd.Stdout = &helper.output
	helper.cmd.Stderr = &helper.output
	if err := helper.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	helper.done = make(chan error, 1)
	go func() { helper.done <- helper.cmd.Wait() }()
	return helper
}

func (h *daemonHelper) killAndWait(t *testing.T) {
	t.Helper()
	if h.waited {
		return
	}
	if err := h.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill daemon helper: %v\n%s", err, h.output.String())
	}
	h.waitErr = <-h.done
	h.waited = true
	if h.waitErr == nil {
		t.Fatalf("daemon helper exited successfully after SIGKILL\n%s", h.output.String())
	}
}

func waitForDaemonSocket(t *testing.T, path string, helper *daemonHelper) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case helper.waitErr = <-helper.done:
			helper.waited = true
			if strings.Contains(strings.ToLower(helper.output.String()), "operation not permitted") {
				t.Skip("sandbox does not permit Unix socket creation")
			}
			t.Fatalf("daemon helper exited before socket became ready: %v\n%s", helper.waitErr, helper.output.String())
		default:
		}
		if time.Now().After(deadline) {
			helper.killAndWait(t)
			t.Fatalf("daemon socket did not become ready: %v\n%s", err, helper.output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func assertPublicIdentityWithoutBackend(t *testing.T, cfg config.Config) {
	t.Helper()
	conn, err := net.DialTimeout("unix", cfg.SocketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(conn)
	keys, err := client.List()
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !bytes.Equal(keys[0].Blob, cfg.PublicKey.Marshal()) {
		t.Fatalf("public identities = %+v, want configured key", keys)
	}
	if _, err := os.Lstat(cfg.BackendSocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity query created backend socket: %v", err)
	}
}

func assertDaemonStatePID(t *testing.T, configPath string, want int) {
	t.Helper()
	got, err := state.Load(filepath.Join(filepath.Dir(configPath), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != want || got.ProviderState != "not_loaded" {
		t.Fatalf("daemon state = %+v, want pid=%d and provider not_loaded", got, want)
	}
}

func writeDaemonTestConfig(t *testing.T, home string) (string, config.Config) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(home, "piv.pub")
	if err := os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(key), 0o644); err != nil {
		t.Fatal(err)
	}

	prefix := filepath.Join(home, "openssh")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if err := os.WriteFile(filepath.Join(prefix, "bin", name), []byte("test dependency"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	providerPath := filepath.Join(home, "libykcs11.dylib")
	if err := os.WriteFile(providerPath, []byte("test provider"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults(home)
	cfg.PublicKeyPath = publicKeyPath
	cfg.OpenSSHPrefix = prefix
	cfg.YKCS11Path = providerPath
	cfg.SocketPath = filepath.Join(home, "agent.sock")
	cfg.BackendSocketPath = filepath.Join(home, "backend.sock")
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, "config.json")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	return configPath, cfg
}
