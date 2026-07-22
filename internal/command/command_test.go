package command

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/agentroute"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/internal/state"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG2Lg3xFnLvrY1W8yZOQ1q0+toWPZyV4lX5JUKbVwS3p test\n"

func TestConfigureAndStatusJSON(t *testing.T) {
	home := t.TempDir()
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o644); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"YUBITOUCH_PUBLIC_KEY":     keyPath,
		"YUBITOUCH_SOCKET":         filepath.Join("/tmp", "yt-command-test-agent.sock"),
		"YUBITOUCH_PIV_SOCKET":     filepath.Join("/tmp", "yt-command-test-piv.sock"),
		"YUBITOUCH_BACKEND_SOCKET": filepath.Join("/tmp", "yt-command-test-backend.sock"),
	}
	env := Environment{
		Home:   home,
		Getenv: func(name string) string { return values[name] },
		ProbeYubiKeys: func(context.Context) (int, error) {
			return 1, nil
		},
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"configure"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("configure exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No PIN was read") {
		t.Fatalf("unexpected configure output: %s", stdout.String())
	}
	logPath := filepath.Join(home, ".ssh", "yubitouch", "yubitouch.log")
	if err := os.WriteFile(logPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"status", "--json"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("status exit %d: %s", code, stderr.String())
	}
	var status Status
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Configured || status.PublicKey == "" {
		t.Fatalf("incomplete status: %+v", status)
	}
	if status.ProviderState != "not_loaded" {
		t.Fatalf("provider state = %q", status.ProviderState)
	}
	if status.YubiKeyState != "connected" || status.YubiKeyCount != 1 {
		t.Fatalf("YubiKey status = %+v", status)
	}
	if status.DiagnosticLog != logPath || status.LogPermissions != "0600" || status.LogSizeBytes != 3 {
		t.Fatalf("diagnostic log status = %+v", status)
	}
}

func TestConfigureDoesNotEchoInvalidAgeSerial(t *testing.T) {
	home := makeBaseCommandConfig(t)
	invalidSerial := "4294967296-sensitive-input"
	values := map[string]string{
		"YUBITOUCH_AGE_SERIAL":    invalidSerial,
		"YUBITOUCH_AGE_SLOT":      "82",
		"YUBITOUCH_AGE_ALGORITHM": "x25519",
	}
	env := Environment{
		Home:   home,
		Getenv: func(name string) string { return values[name] },
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"configure"}, &stdout, &stderr, env); code != ExitConfigError {
		t.Fatalf("configure exit %d, want %d", code, ExitConfigError)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "age.serial must be a canonical non-zero uint32") {
		t.Fatalf("unexpected configure output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), invalidSerial) {
		t.Fatal("configure error exposed the invalid age serial")
	}
}

func TestDoctorReportsAgeRecoveryReferenceSyntaxWithoutExposingReference(t *testing.T) {
	home, path, cfg, _, _ := writeAgeCommandConfig(t, true, true)
	cfg.YKCS11Path = filepath.Join(home, "missing-ykcs11.dylib")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	env := Environment{
		Home:          home,
		Getenv:        func(string) string { return "" },
		ProbeYubiKeys: func(context.Context) (int, error) { return 0, nil },
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"doctor"}, &stdout, &stderr, env); code != ExitRuntimeError {
		t.Fatalf("doctor exit %d, want %d; stderr=%q", code, ExitRuntimeError, stderr.String())
	}
	want := "[OK] age recovery secret reference: syntax is valid; the recovery identity was not resolved"
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("doctor output did not report recovery reference validation: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), cfg.Age.Recovery.IdentityRef) || strings.Contains(stderr.String(), cfg.Age.Recovery.IdentityRef) {
		t.Fatal("doctor output exposed the recovery identity reference")
	}
}

func TestDoctorRejectsInvalidAgeRecoveryReferenceWithoutExposingReference(t *testing.T) {
	home := makeBaseCommandConfig(t)
	path := config.DefaultPath(home)
	cfg, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	invalidReference := "op://vault/item"
	cfg.OnePasswordAccount = "configured account"
	cfg.Age = &config.AgeConfig{
		Serial:    "12345678",
		Slot:      "82",
		Algorithm: "x25519",
		Recovery: &config.AgeRecovery{
			Provider:    "1password",
			IdentityRef: invalidReference,
			Recipient:   "not-reached",
		},
	}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"doctor"}, &stdout, &stderr, Environment{
		Home:   home,
		Getenv: func(string) string { return "" },
	})
	if code != ExitConfigError || !strings.Contains(stderr.String(), "[FAIL] configuration: age.recovery.identity_ref") {
		t.Fatalf("doctor exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), invalidReference) || strings.Contains(stderr.String(), invalidReference) {
		t.Fatal("doctor configuration error exposed the recovery identity reference")
	}
}

func TestYubiKeyStateDistinguishesMissingFromProbeFailure(t *testing.T) {
	state, count := yubiKeyState(0, nil)
	if state != "not_detected" || count != 0 {
		t.Fatalf("missing state = %q, %d", state, count)
	}
	state, count = yubiKeyState(2, errors.New("probe failed"))
	if state != "probe_unavailable" || count != 0 {
		t.Fatalf("failed state = %q, %d", state, count)
	}
}

func TestReportSignFailureMapsSafeExitCodes(t *testing.T) {
	tests := []struct {
		failure string
		code    int
		message string
	}{
		{failure: "device_unavailable", code: ExitDeviceMissing, message: "reconnect"},
		{failure: "provider_initialization", code: ExitPINFailure, message: "PIN/provider"},
		{failure: "key_mismatch", code: ExitKeyMismatch, message: "does not match"},
		{failure: "timeout", code: ExitSignTimeout, message: "timed out"},
		{failure: "canceled", code: ExitSignTimeout, message: "canceled"},
		{failure: "op://Personal/YubiKey/PIN=123456", code: ExitRuntimeError, message: "yubitouch.log"},
	}
	for _, test := range tests {
		t.Run(test.failure, func(t *testing.T) {
			var stderr bytes.Buffer
			code := reportSignFailure(&stderr, test.failure, "/tmp/yubitouch/config.json")
			if code != test.code || !strings.Contains(stderr.String(), test.message) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if strings.Contains(stderr.String(), "op://") || strings.Contains(stderr.String(), "123456") || strings.Contains(stderr.String(), "Personal") {
				t.Fatalf("failure output leaked sensitive text: %s", stderr.String())
			}
		})
	}
}

func TestLastSignFailureClassRejectsStaleState(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	store := state.NewStore(filepath.Join(dir, "state.json"))
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	since := time.Now().UTC()
	store.Handle(signing.Event{
		Type: signing.EventFailure,
		At:   since.Add(-time.Second),
		Err:  errors.New("ssh-add failed"),
	})
	if got := lastSignFailureClass(configPath, since); got != "" {
		t.Fatalf("stale failure class = %q", got)
	}
	store.Handle(signing.Event{
		Type: signing.EventFailure,
		At:   since.Add(time.Second),
		Err:  errors.New("ssh-add failed"),
	})
	if got := lastSignFailureClass(configPath, since); got != "provider_initialization" {
		t.Fatalf("recent failure class = %q", got)
	}
}

func TestLastSignFailureClassAcceptsCanceledState(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	store := state.NewStore(filepath.Join(dir, "state.json"))
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	since := time.Now().UTC()
	store.Handle(signing.Event{
		Type: signing.EventCanceled,
		At:   since.Add(time.Second),
		Err:  signing.ErrCanceled,
	})
	if got := lastSignFailureClass(configPath, since); got != "canceled" {
		t.Fatalf("canceled failure class = %q", got)
	}
}

func TestMergePersistedStateRejectsStaleRuntimeData(t *testing.T) {
	signAt := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	routeAt := signAt.Add(-time.Minute)
	ageAt := signAt.Add(time.Minute)
	persisted := state.State{
		PID:               4242,
		ProviderState:     "loaded",
		LastSignEvent:     "success",
		LastSignAt:        signAt,
		AgentRoute:        "1password",
		RouteProbeState:   "not_detected",
		RouteChangedAt:    routeAt,
		FallbackChecked:   true,
		FallbackReachable: true,
		FallbackKeyFound:  true,
		AgeBackend:        "recovery",
		AgeResult:         "success",
		LastAgeAt:         ageAt,
	}
	stale := Status{ProviderState: "not_loaded"}
	mergePersistedState(&stale, persisted, false)
	if !stale.StateStale || stale.DaemonPID != 0 || stale.ProviderState != "unavailable" {
		t.Fatalf("stale status = %+v", stale)
	}
	if stale.LastSignEvent != "success" || stale.LastSignAt != signAt.Format(time.RFC3339) {
		t.Fatalf("stale history was not retained: %+v", stale)
	}
	if stale.AgentRoute != "" || stale.RouteProbeState != "" || stale.FallbackChecked || stale.FallbackReachable || stale.FallbackKeyFound {
		t.Fatalf("stale route metadata was presented as current: %+v", stale)
	}
	if stale.AgeBackend != "" || stale.AgeResult != "" || stale.LastAgeAt != "" {
		t.Fatalf("stale age operation was presented as current: %+v", stale)
	}

	current := Status{ProviderState: "not_loaded"}
	mergePersistedState(&current, persisted, true)
	if current.StateStale || current.DaemonPID != 4242 || current.ProviderState != "loaded" {
		t.Fatalf("current status = %+v", current)
	}
	if current.AgentRoute != "1password" || current.RouteProbeState != "not_detected" ||
		current.RouteChangedAt != routeAt.Format(time.RFC3339) || !current.FallbackChecked || !current.FallbackReachable || !current.FallbackKeyFound {
		t.Fatalf("current route status = %+v", current)
	}
	if current.AgeBackend != "recovery" || current.AgeResult != "success" || current.LastAgeAt != ageAt.Format(time.RFC3339) {
		t.Fatalf("current age status = %+v", current)
	}
}

func TestPersistedRouteMatchesPhysicalTarget(t *testing.T) {
	tests := []struct {
		persisted string
		physical  agentroute.Route
		want      bool
	}{
		{persisted: "piv", physical: agentroute.RoutePIV, want: true},
		{persisted: "piv_fail_closed", physical: agentroute.RoutePIV, want: true},
		{persisted: "1password", physical: agentroute.Route1Password, want: true},
		{persisted: "1password", physical: agentroute.RoutePIV, want: false},
		{persisted: "piv", physical: agentroute.Route1Password, want: false},
		{persisted: "", physical: agentroute.RoutePIV, want: false},
	}
	for _, test := range tests {
		if got := persistedRouteMatches(test.persisted, test.physical); got != test.want {
			t.Fatalf("persistedRouteMatches(%q, %q) = %v, want %v", test.persisted, test.physical, got, test.want)
		}
	}
}

func TestFallbackRouteContradictsConnectedOrUnknownDeviceState(t *testing.T) {
	if !routeContradictsProbe(agentroute.Route1Password, yubiKeyConnected) ||
		!routeContradictsProbe(agentroute.Route1Password, yubiKeyProbeUnavailable) {
		t.Fatal("unsafe fallback route was not marked contradictory")
	}
	if routeContradictsProbe(agentroute.Route1Password, yubiKeyNotDetected) ||
		routeContradictsProbe(agentroute.RoutePIV, yubiKeyConnected) {
		t.Fatal("safe route state was marked contradictory")
	}
}

func TestStatusKeepsPhysicalRouteWhenPersistedRouteMismatches(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-status-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	runtimeDir := filepath.Join(home, ".ssh", "yubitouch")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.FallbackAgent = config.FallbackAgent1Password
	cfg.FallbackAgentSocket = filepath.Join(runtimeDir, "fallback.sock")
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(config.DefaultPath(home), cfg); err != nil {
		t.Fatal(err)
	}
	pivListener := listenStatusSocket(t, cfg.PIVSocketPath)
	defer pivListener.Close()
	router := agentroute.New(cfg, agentroute.Options{
		Probe:     func(context.Context) (int, error) { return 1, nil },
		GuardPath: agentroute.GuardPath(config.DefaultPath(home)),
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	store := state.NewStore(filepath.Join(runtimeDir, "state.json"))
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	store.SetRoute(agentroute.Snapshot{
		Route:      agentroute.Route1Password,
		ProbeState: agentroute.ProbeNotDetected,
		ChangedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	})

	env := Environment{
		Home:   home,
		Getenv: func(string) string { return "" },
		ProbeYubiKeys: func(context.Context) (int, error) {
			return 1, nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := runStatus(&stdout, &stderr, env, true); code != ExitOK {
		t.Fatalf("status exit %d: %s", code, stderr.String())
	}
	var got Status
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AgentRoute != string(agentroute.RoutePIV) || !got.RouteGuardReady || !got.RouteStateStale || !got.StateStale || got.DaemonPID != 0 {
		t.Fatalf("mismatched route status = %+v", got)
	}
}

func listenStatusSocket(t *testing.T, path string) net.Listener {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	return listener
}

func TestContainsTargetKeyAllowsOtherListedIdentities(t *testing.T) {
	target, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	keys := []*agent.Key{
		{Format: ssh.KeyAlgoED25519, Blob: []byte("not-the-target")},
		{Format: target.Type(), Blob: target.Marshal()},
	}
	if !containsTargetKey(keys, target.Marshal()) {
		t.Fatal("target key was not found among multiple identities")
	}
	if containsTargetKey(keys[:1], target.Marshal()) {
		t.Fatal("non-target identity matched")
	}
}

func TestSignAllowsMissingDeviceOnDirectFallbackRoute(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-test-sign-fallback-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	runtimeDir := filepath.Join(home, ".ssh", "yubitouch")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, ssh.MarshalAuthorizedKey(publicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.FallbackAgent = config.FallbackAgent1Password
	cfg.FallbackAgentSocket = filepath.Join(runtimeDir, "fallback.sock")
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(config.DefaultPath(home), cfg); err != nil {
		t.Fatal(err)
	}
	pivListener := listenStatusSocket(t, cfg.PIVSocketPath)
	defer pivListener.Close()
	fallbackListener := serveCommandAgent(t, cfg.FallbackAgentSocket, private)
	defer fallbackListener.Close()
	router := agentroute.New(cfg, agentroute.Options{
		Probe:       func(context.Context) (int, error) { return 0, nil },
		ProbeEvents: make(chan struct{}),
		InspectFallback: func(context.Context, config.Config) (agentroute.FallbackReport, error) {
			return agentroute.FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
		DebounceCount: 1,
		PollInterval:  time.Hour,
		GuardPath:     agentroute.GuardPath(config.DefaultPath(home)),
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
	cancelRouter()
	if err := <-routerDone; err != nil {
		t.Fatal(err)
	}
	if router.Current().Route != agentroute.Route1Password {
		t.Fatalf("router did not enter fallback: %+v", router.Current())
	}
	env := Environment{
		Home:   home,
		Getenv: func(string) string { return "" },
		ProbeYubiKeys: func(context.Context) (int, error) {
			return 0, nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := runTestSign(&stdout, &stderr, env); code != ExitOK {
		t.Fatalf("test-sign exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "succeeded") {
		t.Fatalf("test-sign output = %q", stdout.String())
	}
}

func serveCommandAgent(t *testing.T, path string, privateKey any) net.Listener {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = agent.ServeAgent(keyring, conn)
			}(connection)
		}
	}()
	return listener
}

func TestProcessAliveRecognizesCurrentProcess(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("current process was reported dead")
	}
	if processAlive(-1) {
		t.Fatal("invalid process was reported alive")
	}
}

func TestMissingConfigIsConfigError(t *testing.T) {
	env := Environment{Home: t.TempDir(), Getenv: func(string) string { return "" }}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"status"}, &stdout, &stderr, env); code != ExitConfigError {
		t.Fatalf("status exit %d, want %d", code, ExitConfigError)
	}
	if !strings.Contains(stderr.String(), "not configured") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}
