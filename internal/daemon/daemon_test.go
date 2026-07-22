package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/agehelper"
	"github.com/mofelee/yubitouch/internal/ageipc"
	"github.com/mofelee/yubitouch/internal/agentproxy"
	"github.com/mofelee/yubitouch/internal/agentroute"
	"github.com/mofelee/yubitouch/internal/ageprofile"
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

	if info, err := os.Lstat(cfg.SocketPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("crash did not leave the managed public route: info=%v err=%v", info, err)
	}
	target, err := os.Readlink(cfg.SocketPath)
	if err != nil {
		t.Fatalf("read public route target: %v", err)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(cfg.SocketPath), target)
	}
	if filepath.Clean(target) != filepath.Clean(cfg.PIVSocketPath) {
		t.Fatalf("public route target = %q, want %q", target, cfg.PIVSocketPath)
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

func TestDaemonRecoversAgeSocketAfterCrash(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-daemon-age-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	configPath, cfg := writeDaemonTestConfig(t, dir)
	scalar := bytes.Repeat([]byte{0x5a}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(scalar)
	clear(scalar)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Age = &config.AgeConfig{
		Serial:    "123456",
		Slot:      "82",
		Algorithm: "x25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
	}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	ageSocket := filepath.Join(filepath.Dir(configPath), "age.sock")

	first := startDaemonHelper(t, dir, configPath)
	t.Cleanup(func() { first.killAndWait(t) })
	waitForDaemonSocket(t, cfg.SocketPath, first)
	waitForDaemonSocket(t, ageSocket, first)
	first.killAndWait(t)
	if info, err := os.Lstat(ageSocket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("crash did not leave the age socket: info=%v err=%v", info, err)
	}

	second := startDaemonHelper(t, dir, configPath)
	t.Cleanup(func() { second.killAndWait(t) })
	waitForDaemonSocket(t, cfg.SocketPath, second)
	waitForDaemonSocket(t, ageSocket, second)
}

func TestMapHelperErrorUsesOnlyPredefinedIPCClasses(t *testing.T) {
	tests := []struct {
		mode  agehelper.Mode
		class agehelper.ErrorClass
		want  ageipc.ErrorClass
	}{
		{agehelper.ModeHardware, agehelper.ErrorInvalidRequest, ageipc.ClassInvalidRequest},
		{agehelper.ModeHardware, agehelper.ErrorConfiguration, ageipc.ClassConfiguration},
		{agehelper.ModeHardware, agehelper.ErrorPINProvider, ageipc.ClassPINFailed},
		{agehelper.ModeHardware, agehelper.ErrorHardwarePIN, ageipc.ClassPINFailed},
		{agehelper.ModeHardware, agehelper.ErrorHardwareMismatch, ageipc.ClassTargetMismatch},
		{agehelper.ModeHardware, agehelper.ErrorUnwrap, ageipc.ClassHardwareFailed},
		{agehelper.ModeRecovery, agehelper.ErrorRecoveryUnavailable, ageipc.ClassRecoveryUnavailable},
		{agehelper.ModeRecovery, agehelper.ErrorRecoveryMismatch, ageipc.ClassRecoveryFailed},
		{agehelper.ModeRecovery, agehelper.ErrorUnwrap, ageipc.ClassRecoveryFailed},
		{agehelper.ModeRecovery, agehelper.ErrorCanceled, ageipc.ClassCanceled},
		{agehelper.ModeRecovery, agehelper.ErrorTimeout, ageipc.ClassTimeout},
		{agehelper.ModeRecovery, agehelper.ErrorClass("op://private/reference"), ageipc.ClassInternal},
	}
	for _, test := range tests {
		if got := mapHelperError(test.mode, test.class); got != test.want {
			t.Fatalf("mapHelperError(%q, %q) = %q, want %q", test.mode, test.class, got, test.want)
		}
	}
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
	cfg.PIVSocketPath = filepath.Join(home, "piv-agent.sock")
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

func TestShutdownServicesWaitsBeforeFailClosedAndListenerClose(t *testing.T) {
	var order []string
	results := make(chan error, 2)
	router := startBackgroundService(context.Background(), results, func(ctx context.Context) error {
		<-ctx.Done()
		order = append(order, "router_stopped")
		return nil
	})
	server := startBackgroundService(context.Background(), results, func(ctx context.Context) error {
		<-ctx.Done()
		order = append(order, "server_stopped")
		return nil
	})

	err := shutdownServices(
		router,
		func() error {
			order = append(order, "route_fail_closed")
			return nil
		},
		server,
		nil,
		func() error {
			order = append(order, "listener_closed")
			return nil
		},
		func() error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"router_stopped", "route_fail_closed", "server_stopped", "listener_closed"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("shutdown order = %v, want %v", order, want)
	}
}

func TestShutdownCancelsAgeBeforeWaitingForSSHServer(t *testing.T) {
	results := make(chan error, 3)
	router := startBackgroundService(context.Background(), results, func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	})
	serverCanceled := make(chan struct{})
	releaseServer := make(chan struct{})
	server := startBackgroundService(context.Background(), results, func(ctx context.Context) error {
		<-ctx.Done()
		close(serverCanceled)
		<-releaseServer
		return nil
	})
	ageCanceled := make(chan struct{})
	ageServer := startBackgroundService(context.Background(), results, func(ctx context.Context) error {
		<-ctx.Done()
		close(ageCanceled)
		return nil
	})
	done := make(chan error, 1)
	go func() {
		done <- shutdownServices(
			router,
			func() error { return nil },
			server,
			ageServer,
			func() error { return nil },
			func() error { return nil },
		)
	}()
	select {
	case <-ageCanceled:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for SSH before canceling queued age work")
	}
	select {
	case <-serverCanceled:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel SSH server")
	}
	close(releaseServer)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestShutdownAcceptsAlreadyClosedUnixListeners(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-shutdown-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sshListener, err := net.Listen("unix", filepath.Join(dir, "ssh.sock"))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	ageListener, err := net.Listen("unix", filepath.Join(dir, "age.sock"))
	if err != nil {
		_ = sshListener.Close()
		if errors.Is(err, os.ErrPermission) {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	sshServer := &agentproxy.Server{
		TargetKey: target,
		BackendFactory: func(context.Context) (agentproxy.Backend, error) {
			return nil, errors.New("unused test backend")
		},
		Coordinator: signing.New(nil, nil, time.Second),
	}
	ageServer := &ageipc.Server{
		Handler: ageipc.HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ageipc.ErrorClass) {
			return nil, ageipc.ClassInternal
		}),
	}
	results := make(chan error, 2)
	sshService := startBackgroundService(context.Background(), results, func(ctx context.Context) error {
		return sshServer.Serve(ctx, sshListener)
	})
	ageService := startBackgroundService(context.Background(), results, func(ctx context.Context) error {
		return ageServer.Serve(ctx, ageListener)
	})

	err = shutdownServices(
		nil,
		func() error { return nil },
		sshService,
		ageService,
		listenerCloser(sshListener),
		listenerCloser(ageListener),
	)
	if err != nil {
		t.Fatalf("normal Unix listener shutdown failed: %v", err)
	}
}

type closeErrorListener struct {
	err error
}

func (l closeErrorListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l closeErrorListener) Close() error              { return l.err }
func (closeErrorListener) Addr() net.Addr              { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestListenerCloserIgnoresOnlyClosedErrors(t *testing.T) {
	wrappedClosed := closeErrorListener{err: errors.New("close: " + net.ErrClosed.Error())}
	if err := listenerCloser(wrappedClosed)(); err == nil {
		t.Fatal("non-wrapping lookalike net.ErrClosed error was ignored")
	}

	wrappedClosed.err = fmt.Errorf("close: %w", net.ErrClosed)
	if err := listenerCloser(wrappedClosed)(); err != nil {
		t.Fatalf("wrapped net.ErrClosed was returned: %v", err)
	}

	want := errors.New("close failed")
	if err := listenerCloser(closeErrorListener{err: want})(); !errors.Is(err, want) {
		t.Fatalf("listener close error = %v, want %v", err, want)
	}
}

func TestDaemonFailClosesGuardBeforeLoadingInvalidConfig(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-daemon-guard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	configPath, cfg := writeDaemonTestConfig(t, dir)
	cfg.FallbackAgent = config.FallbackAgent1Password
	cfg.FallbackAgentSocket = filepath.Join(dir, "fallback.sock")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	pivListener := listenDaemonTestSocket(t, cfg.PIVSocketPath)
	defer pivListener.Close()
	fallbackListener := listenDaemonTestSocket(t, cfg.FallbackAgentSocket)
	defer fallbackListener.Close()

	router := agentroute.New(cfg, agentroute.Options{
		Probe:       func(context.Context) (int, error) { return 0, nil },
		ProbeEvents: make(chan struct{}),
		InspectFallback: func(context.Context, config.Config) (agentroute.FallbackReport, error) {
			return agentroute.FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
		DebounceCount: 1,
		PollInterval:  5 * time.Millisecond,
		GuardPath:     agentroute.GuardPath(configPath),
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	routerCtx, cancelRouter := context.WithCancel(context.Background())
	routerDone := make(chan error, 1)
	go func() { routerDone <- router.Run(routerCtx) }()
	deadline := time.Now().Add(time.Second)
	for router.Current().Route != agentroute.Route1Password && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if router.Current().Route != agentroute.Route1Password {
		cancelRouter()
		t.Fatalf("router did not enter fallback: %+v", router.Current())
	}
	cancelRouter()
	if err := <-routerDone; err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(configPath, []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), Options{ConfigPath: configPath, Home: dir, Executable: "/bin/false"})
	if err == nil {
		t.Fatal("daemon accepted invalid configuration")
	}
	report, routeErr := agentroute.InspectPublicRoute(cfg)
	if routeErr != nil || report.Route != agentroute.RoutePIV || !report.TargetReachable {
		t.Fatalf("guard did not fail close before config load: report=%+v error=%v", report, routeErr)
	}
}

func listenDaemonTestSocket(t *testing.T, path string) net.Listener {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	return listener
}
