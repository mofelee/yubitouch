package agentroute

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mofelee/yubitouch/internal/config"
)

func TestFailClosedFromGuardDoesNotNeedValidConfig(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{})
	guardPath := GuardPath(filepath.Join(dir, "config.json"))
	router := New(cfg, Options{
		Probe: func(context.Context) (int, error) { return 0, nil },
		InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
			return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
		DebounceCount: 1,
		GuardPath:     guardPath,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfg, Route1Password)

	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.PIVSocketPath); err != nil {
		t.Fatal(err)
	}
	if err := FailClosedFromGuard(guardPath); err != nil {
		t.Fatal(err)
	}
	assertLinkTarget(t, cfg.SocketPath, cfg.PIVSocketPath)
	if socketReachable(cfg.SocketPath) {
		t.Fatal("fail-closed route remained reachable through 1Password")
	}
	info, err := os.Lstat(guardPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("guard mode = %v", info.Mode())
	}
}

func TestRouterGuardMigratesFallbackAtoB(t *testing.T) {
	dir := tempDir(t)
	cfgA := routeConfig(dir, newPublicKey(t))
	cfgA.FallbackAgentSocket = filepath.Join(dir, "fallback-a.sock")
	cfgB := cfgA
	cfgB.FallbackAgentSocket = filepath.Join(dir, "fallback-b.sock")
	serveAgent(t, cfgA.PIVSocketPath, &testAgent{})
	serveAgent(t, cfgA.FallbackAgentSocket, &testAgent{})
	serveAgent(t, cfgB.FallbackAgentSocket, &testAgent{})
	guardPath := GuardPath(filepath.Join(dir, "config.json"))

	newRouter := func(cfg config.Config) *Router {
		return New(cfg, Options{
			Probe: func(context.Context) (int, error) { return 0, nil },
			InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
				return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
			},
			DebounceCount: 1,
			GuardPath:     guardPath,
		})
	}
	first := newRouter(cfgA)
	if err := first.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := first.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfgA, Route1Password)

	second := newRouter(cfgB)
	if err := second.Initialize(); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfgB, RoutePIV)
	if err := ValidateGuard(guardPath, cfgB); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGuard(guardPath, cfgA); err == nil {
		t.Fatal("guard still matches fallback A")
	}
	if err := second.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfgB, Route1Password)
}

func TestRouterGuardDisablesStaleFallback(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{})
	guardPath := GuardPath(filepath.Join(dir, "config.json"))
	enabled := New(cfg, Options{
		Probe: func(context.Context) (int, error) { return 0, nil },
		InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
			return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
		DebounceCount: 1,
		GuardPath:     guardPath,
	})
	if err := enabled.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := enabled.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfg, Route1Password)

	disabledCfg := cfg
	disabledCfg.FallbackAgent = config.FallbackAgentNone
	disabledCfg.FallbackAgentSocket = ""
	disabled := New(disabledCfg, Options{
		Probe:     func(context.Context) (int, error) { return 0, nil },
		GuardPath: guardPath,
	})
	if err := disabled.Initialize(); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, disabledCfg, RoutePIV)
	if err := ValidateGuard(guardPath, disabledCfg); err != nil {
		t.Fatal(err)
	}
	record, err := readGuard(guardPath)
	if err != nil {
		t.Fatal(err)
	}
	if record.FallbackSocket != "" {
		t.Fatalf("disabled guard retained fallback %q", record.FallbackSocket)
	}
}

func TestEnabledFallbackRequiresGuard(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	router := New(cfg, Options{Probe: func(context.Context) (int, error) { return 1, nil }})
	if err := router.Initialize(); err == nil || !strings.Contains(err.Error(), "guard") {
		t.Fatalf("missing guard error = %v", err)
	}
}

func TestRouterFailsClosedWhenGuardDisappearsOrIsCorrupted(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "deleted",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "corrupted",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("not-json\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := tempDir(t)
			cfg := routeConfig(dir, newPublicKey(t))
			serveAgent(t, cfg.PIVSocketPath, &testAgent{})
			serveAgent(t, cfg.FallbackAgentSocket, &testAgent{})
			guardPath := GuardPath(filepath.Join(dir, "config.json"))
			router := New(cfg, Options{
				Probe: func(context.Context) (int, error) { return 0, nil },
				InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
					return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
				},
				DebounceCount: 1,
				GuardPath:     guardPath,
			})
			if err := router.Initialize(); err != nil {
				t.Fatal(err)
			}
			if err := router.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertRoute(t, cfg, Route1Password)

			test.mutate(t, guardPath)
			err := router.reconcile(context.Background())
			if err == nil || !strings.Contains(err.Error(), "guard") {
				t.Fatalf("invalid guard reconcile error = %v", err)
			}
			if got := router.Current(); got.Route != RoutePIVFailClosed {
				t.Fatalf("invalid guard snapshot = %+v", got)
			}
			assertRoute(t, cfg, RoutePIV)
		})
	}
}

func TestInspectPublicRouteRejectsDisabledFallback(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{})
	if err := atomicRoute(cfg.SocketPath, cfg.FallbackAgentSocket); err != nil {
		t.Fatal(err)
	}
	cfg.FallbackAgent = config.FallbackAgentNone
	report, err := InspectPublicRoute(cfg)
	if err == nil || report.Route == Route1Password {
		t.Fatalf("disabled fallback report = %+v, error = %v", report, err)
	}
}

func TestAtomicRouteRejectsConcurrentUnmanagedReplacement(t *testing.T) {
	dir := tempDir(t)
	publicPath := filepath.Join(dir, "agent.sock")
	first := filepath.Join(dir, "first.sock")
	second := filepath.Join(dir, "second.sock")
	if err := atomicRoute(publicPath, first); err != nil {
		t.Fatal(err)
	}
	var hookErr error
	err := atomicRouteWithHook(publicPath, second, []string{first}, func() {
		if removeErr := os.Remove(publicPath); removeErr != nil {
			hookErr = removeErr
			return
		}
		hookErr = os.WriteFile(publicPath, []byte("unmanaged"), 0o600)
	})
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("concurrent replacement error = %v", err)
	}
	data, readErr := os.ReadFile(publicPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "unmanaged" {
		t.Fatalf("concurrent file contents = %q", data)
	}
}

func TestAtomicRouteMigratesSameStaleSocket(t *testing.T) {
	dir := tempDir(t)
	publicPath := filepath.Join(dir, "legacy-agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: publicPath, Net: "unix"})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(publicPath) })
	target := filepath.Join(dir, "piv-agent.sock")
	if err := atomicRoute(publicPath, target); err != nil {
		t.Fatal(err)
	}
	assertLinkTarget(t, publicPath, target)
}

func TestFailClosedFromGuardRejectsInvalidGuard(t *testing.T) {
	dir := tempDir(t)
	path := GuardPath(filepath.Join(dir, "config.json"))
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := FailClosedFromGuard(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("invalid guard error = %v", err)
	}
}

func assertLinkTarget(t *testing.T, path string, want string) {
	t.Helper()
	target, err := resolvedLinkTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Clean(want) {
		t.Fatalf("link target = %q, want %q", target, want)
	}
}

func TestGuardPathUsesConfigRuntimeDirectory(t *testing.T) {
	dir := tempDir(t)
	got := GuardPath(filepath.Join(dir, "custom.json"))
	want := filepath.Join(dir, guardFileName)
	if got != want {
		t.Fatalf("GuardPath = %q, want %q", got, want)
	}
}
