package agentroute

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type testAgent struct {
	keys []*agent.Key
}

func (a *testAgent) List() ([]*agent.Key, error) {
	result := make([]*agent.Key, len(a.keys))
	for i, key := range a.keys {
		result[i] = &agent.Key{Format: key.Format, Blob: append([]byte(nil), key.Blob...), Comment: key.Comment}
	}
	return result, nil
}

func (a *testAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return nil, errors.New("sign must not be called")
}
func (a *testAgent) Add(agent.AddedKey) error       { return errors.New("disabled") }
func (a *testAgent) Remove(ssh.PublicKey) error     { return errors.New("disabled") }
func (a *testAgent) RemoveAll() error               { return errors.New("disabled") }
func (a *testAgent) Lock([]byte) error              { return errors.New("disabled") }
func (a *testAgent) Unlock([]byte) error            { return errors.New("disabled") }
func (a *testAgent) Signers() ([]ssh.Signer, error) { return nil, errors.New("disabled") }

func TestInspectFallbackMatchesOnlyTargetAndRejectsSymlink(t *testing.T) {
	target := newPublicKey(t)
	other := newPublicKey(t)
	dir := tempDir(t)
	socket := filepath.Join(dir, "fallback.sock")
	serveAgent(t, socket, &testAgent{keys: []*agent.Key{agentKey(other), agentKey(target)}})
	cfg := routeConfig(dir, target)
	cfg.FallbackAgentSocket = socket

	report, err := InspectFallback(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Reachable || !report.TargetKeyFound || report.OtherKeys != 1 {
		t.Fatalf("fallback report = %+v", report)
	}

	alias := filepath.Join(dir, "fallback-alias.sock")
	if err := os.Symlink(socket, alias); err != nil {
		t.Fatal(err)
	}
	cfg.FallbackAgentSocket = alias
	if _, err := InspectFallback(context.Background(), cfg); !errors.Is(err, ErrFallbackUnavailable) {
		t.Fatalf("symlink fallback error = %v", err)
	}
}

func TestInspectFallbackRejectsUnsafeParentDirectory(t *testing.T) {
	target := newPublicKey(t)
	dir := tempDir(t)

	realParent := filepath.Join(dir, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	realSocket := filepath.Join(realParent, "fallback.sock")
	serveAgent(t, realSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	linkedParent := filepath.Join(dir, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	cfg := routeConfig(dir, target)
	cfg.FallbackAgentSocket = filepath.Join(linkedParent, "fallback.sock")
	if _, err := InspectFallback(context.Background(), cfg); !errors.Is(err, ErrFallbackUnavailable) || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("symlink parent error = %v", err)
	}

	writableParent := filepath.Join(dir, "writable")
	if err := os.Mkdir(writableParent, 0o700); err != nil {
		t.Fatal(err)
	}
	writableSocket := filepath.Join(writableParent, "fallback.sock")
	serveAgent(t, writableSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	if err := os.Chmod(writableParent, 0o770); err != nil {
		t.Fatal(err)
	}
	cfg.FallbackAgentSocket = writableSocket
	if _, err := InspectFallback(context.Background(), cfg); !errors.Is(err, ErrFallbackUnavailable) || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable parent error = %v", err)
	}
}

func TestOwnedByCurrentUserFailsClosedWithoutStat(t *testing.T) {
	info, err := os.Stat(tempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if ownedByCurrentUser(fileInfoWithoutStat{FileInfo: info}) {
		t.Fatal("missing syscall.Stat_t was accepted")
	}
}

func TestRouterDebouncesMissingDeviceAndFailsClosed(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})

	var count atomic.Int32
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) {
			return int(count.Load()), nil
		},
		DebounceCount: 2,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfg, RoutePIV)
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := router.Current().Route; got != RoutePIVFailClosed {
		t.Fatalf("first missing probe route = %q", got)
	}
	if router.Current().FallbackChecked {
		t.Fatal("fallback was marked checked before debounce completed")
	}
	assertRoute(t, cfg, RoutePIV)
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := router.Current().Route; got != Route1Password {
		t.Fatalf("debounced route = %q", got)
	}
	if !router.Current().FallbackChecked {
		t.Fatal("fallback inspection was not recorded")
	}
	assertRoute(t, cfg, Route1Password)

	count.Store(1)
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := router.Current().Route; got != RoutePIV {
		t.Fatalf("reconnected route = %q", got)
	}
	if router.Current().FallbackChecked {
		t.Fatal("reconnected PIV route retained stale fallback-checked state")
	}
	assertRoute(t, cfg, RoutePIV)

	router.probe = func(context.Context) (int, error) { return 0, errors.New("probe failed") }
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := router.Current().Route; got != RoutePIVFailClosed {
		t.Fatalf("probe failure route = %q", got)
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestFallbackDisabledNeverInspectsFallback(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	cfg.FallbackAgent = config.FallbackAgentNone
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	inspections := 0
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) { return 0, nil },
		InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
			inspections++
			return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inspections != 0 || router.Current().Route != RoutePIV {
		t.Fatalf("disabled fallback inspections=%d route=%q", inspections, router.Current().Route)
	}
	if router.Current().FallbackChecked {
		t.Fatal("disabled fallback was marked checked")
	}
}

func TestConnectedDeviceDoesNotInspectEnabledFallback(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	inspections := 0
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) { return 1, nil },
		InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
			inspections++
			return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inspections != 0 || router.Current().Route != RoutePIV || router.Current().ProbeState != ProbeConnected {
		t.Fatalf("enabled fallback inspections=%d snapshot=%+v", inspections, router.Current())
	}
	if router.Current().FallbackChecked {
		t.Fatal("connected-device route incorrectly reports a fallback inspection")
	}
}

func TestFallbackValidationFailureKeepsPIVRoute(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(newPublicKey(t))}})
	router := newGuardedRouter(dir, cfg, Options{
		Probe:         func(context.Context) (int, error) { return 0, nil },
		DebounceCount: 1,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := router.Current()
	if got.Route != RoutePIVFailClosed || !got.FallbackChecked || !got.FallbackReachable || got.FallbackKeyFound {
		t.Fatalf("invalid fallback snapshot = %+v", got)
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestFallbackWithOtherIdentitiesKeepsPIVRoute(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{
		agentKey(target),
		agentKey(newPublicKey(t)),
	}})
	router := newGuardedRouter(dir, cfg, Options{
		Probe:         func(context.Context) (int, error) { return 0, nil },
		DebounceCount: 1,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := router.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := router.Current()
	if got.Route != RoutePIVFailClosed || !got.FallbackChecked || !got.FallbackReachable || !got.FallbackKeyFound || got.FallbackOtherKeys != 1 {
		t.Fatalf("fallback with other identities snapshot = %+v", got)
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestRouterRunReportsTransientErrorsAndRetries(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})

	errorsSeen := make(chan error, 1)
	router := newGuardedRouter(dir, cfg, Options{
		Probe:        func(context.Context) (int, error) { return 1, nil },
		ProbeEvents:  make(chan struct{}),
		PollInterval: 5 * time.Millisecond,
		OnError: func(err error) {
			select {
			case errorsSeen <- err:
			default:
			}
		},
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	initialUpdate := router.Current().UpdatedAt
	if err := os.Remove(cfg.PIVSocketPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	select {
	case err := <-errorsSeen:
		if !strings.Contains(err.Error(), "route target is unsafe") {
			t.Fatalf("reported error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transient route error was not reported")
	}
	select {
	case err := <-done:
		t.Fatalf("router stopped after transient error: %v", err)
	default:
	}

	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	deadline := time.Now().Add(time.Second)
	for !router.Current().UpdatedAt.After(initialUpdate) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := router.Current(); !got.UpdatedAt.After(initialUpdate) || got.Route != RoutePIV || got.ProbeState != ProbeConnected {
		t.Fatalf("router did not recover after transient error: %+v", got)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("router did not stop after cancellation")
	}
}

func TestRouterRetriesTransientProbeFailure(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	events := make(chan struct{})
	retryProbe := make(chan struct{})
	var probes atomic.Int32
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(ctx context.Context) (int, error) {
			if probes.Add(1) == 1 {
				return 0, errors.New("transient IOKit failure")
			}
			select {
			case <-retryProbe:
				return 1, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		},
		ProbeEvents:  events,
		PollInterval: 5 * time.Millisecond,
		ProbeTimeout: time.Second,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIVFailClosed && snapshot.ProbeState == ProbeUnavailable
	})
	deadline := time.Now().Add(time.Second)
	for probes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("probe calls before retry release = %d, want 2", got)
	}
	close(retryProbe)
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})
	assertRoute(t, cfg, RoutePIV)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterRequiresDeviceEventsWhenFallbackIsEnabled(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) { return 1, nil },
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := router.Run(context.Background()); !errors.Is(err, ErrProbeEventsRequired) {
		t.Fatalf("missing device events error = %v", err)
	}
	got := router.Current()
	if got.Route != RoutePIVFailClosed || got.ProbeState != ProbeUnavailable {
		t.Fatalf("missing device events snapshot = %+v", got)
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestRouterDoesNotProbeDuringCoordinatedSigning(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	events := make(chan struct{}, 1)
	var probes atomic.Int32
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) {
			probes.Add(1)
			return 1, nil
		},
		ProbeEvents:  events,
		PollInterval: 5 * time.Millisecond,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})

	signCtx, cancelSign := context.WithCancel(context.Background())
	defer cancelSign()
	signStarted := make(chan struct{})
	signDone := make(chan error, 1)
	coordinator := signing.New(nil, nil, time.Second)
	go func() {
		_, err := coordinator.Sign(signCtx, func() (*ssh.Signature, error) {
			close(signStarted)
			<-signCtx.Done()
			return nil, signCtx.Err()
		})
		signDone <- err
	}()
	select {
	case <-signStarted:
	case <-time.After(time.Second):
		t.Fatal("coordinated sign did not start")
	}

	// Keep the PIV operation active across several intervals used by the old
	// polling router. No device probe should run without an IOKit event.
	time.Sleep(30 * time.Millisecond)
	if got := probes.Load(); got != 1 {
		t.Fatalf("router probes during coordinated sign = %d, want 1", got)
	}
	cancelSign()
	select {
	case err := <-signDone:
		if !errors.Is(err, signing.ErrCanceled) {
			t.Fatalf("coordinated sign error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("coordinated sign did not stop")
	}

	events <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for probes.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("probe calls after device event = %d, want 2", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterBufferedRemovalWaitsForDebounceTimer(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	events := make(chan struct{}, 1)
	events <- struct{}{}
	var probes atomic.Int32
	var inspections atomic.Int32
	var updates atomic.Int32
	bufferedRemovalReconciled := make(chan struct{})
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) {
			probes.Add(1)
			return 0, nil
		},
		ProbeEvents: events,
		InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
			inspections.Add(1)
			return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
		PollInterval:  50 * time.Millisecond,
		DebounceCount: 2,
		Now: func() time.Time {
			call := updates.Add(1)
			if call == 3 {
				close(bufferedRemovalReconciled)
			}
			return time.Unix(int64(call), 0)
		},
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	select {
	case <-bufferedRemovalReconciled:
	case <-time.After(time.Second):
		t.Fatal("buffered removal was not reconciled")
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("probe calls after buffered removal = %d, want 2", got)
	}
	if got := router.Current(); got.Route != RoutePIVFailClosed || got.ProbeState != ProbeNotDetected || got.FallbackChecked {
		t.Fatalf("buffered removal bypassed debounce: %+v", got)
	}
	if got := inspections.Load(); got != 0 {
		t.Fatalf("fallback inspections before debounce timer = %d, want 0", got)
	}
	assertRoute(t, cfg, RoutePIV)
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == Route1Password && snapshot.FallbackChecked
	})
	if got := inspections.Load(); got != 1 {
		t.Fatalf("fallback inspections after debounce timer = %d, want 1", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterDeviceRemovalDebouncesAndReinsertCancelsFallback(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	events := make(chan struct{}, 1)
	var count atomic.Int32
	count.Store(1)
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) {
			return int(count.Load()), nil
		},
		ProbeEvents:   events,
		PollInterval:  30 * time.Millisecond,
		DebounceCount: 2,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})

	count.Store(0)
	events <- struct{}{}
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIVFailClosed && snapshot.ProbeState == ProbeNotDetected && !snapshot.FallbackChecked
	})
	assertRoute(t, cfg, RoutePIV)

	count.Store(1)
	events <- struct{}{}
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})
	time.Sleep(45 * time.Millisecond)
	if got := router.Current(); got.Route != RoutePIV || got.ProbeState != ProbeConnected {
		t.Fatalf("reinsert during debounce reached fallback: %+v", got)
	}

	count.Store(0)
	events <- struct{}{}
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == Route1Password && snapshot.ProbeState == ProbeNotDetected && snapshot.FallbackChecked
	})
	assertRoute(t, cfg, Route1Password)

	count.Store(1)
	events <- struct{}{}
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})
	assertRoute(t, cfg, RoutePIV)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterReinsertInterruptsFallbackInspection(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	events := make(chan struct{}, 1)
	inspectionStarted := make(chan struct{}, 1)
	inspectionCanceled := make(chan struct{}, 1)
	var count atomic.Int32
	count.Store(1)
	var fallbackRouteSeen atomic.Bool
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) {
			return int(count.Load()), nil
		},
		ProbeEvents: events,
		InspectFallback: func(ctx context.Context, _ config.Config) (FallbackReport, error) {
			inspectionStarted <- struct{}{}
			<-ctx.Done()
			inspectionCanceled <- struct{}{}
			return FallbackReport{}, ctx.Err()
		},
		PollInterval:  10 * time.Millisecond,
		ProbeTimeout:  time.Second,
		DebounceCount: 2,
		OnUpdate: func(snapshot Snapshot) {
			if snapshot.Route == Route1Password {
				fallbackRouteSeen.Store(true)
			}
		},
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})
	count.Store(0)
	events <- struct{}{}
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIVFailClosed && snapshot.ProbeState == ProbeNotDetected && !snapshot.FallbackChecked
	})
	assertRoute(t, cfg, RoutePIV)
	select {
	case <-inspectionStarted:
	case <-time.After(time.Second):
		t.Fatal("fallback inspection did not start")
	}
	count.Store(1)
	events <- struct{}{}
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})
	select {
	case <-inspectionCanceled:
	case <-time.After(time.Second):
		t.Fatal("fallback inspection was not canceled after reinsert")
	}
	if fallbackRouteSeen.Load() {
		t.Fatal("router published fallback after a reinsert during fallback inspection")
	}
	assertRoute(t, cfg, RoutePIV)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterRechecksDeviceBeforePublishingFallback(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	inspectionStarted := make(chan struct{})
	releaseInspection := make(chan struct{})
	var count atomic.Int32
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) {
			return int(count.Load()), nil
		},
		ProbeEvents: make(chan struct{}),
		InspectFallback: func(ctx context.Context, _ config.Config) (FallbackReport, error) {
			close(inspectionStarted)
			select {
			case <-releaseInspection:
				return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
			case <-ctx.Done():
				return FallbackReport{}, ctx.Err()
			}
		},
		DebounceCount: 1,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	reconcileCtx, cancelReconcile := context.WithCancel(context.Background())
	defer cancelReconcile()
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- router.reconcile(reconcileCtx) }()
	select {
	case <-inspectionStarted:
	case <-time.After(time.Second):
		t.Fatal("fallback inspection did not start")
	}
	count.Store(1)
	close(releaseInspection)
	if err := <-reconcileDone; err != nil {
		t.Fatal(err)
	}
	got := router.Current()
	if got.Route != RoutePIV || got.ProbeState != ProbeConnected || got.FallbackChecked {
		t.Fatalf("route after final device recheck = %+v", got)
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestRouterRejectsFallbackWhenEventStreamClosesDuringFinalProbe(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	events := make(chan struct{})
	finalProbeStarted := make(chan struct{})
	releaseFinalProbe := make(chan struct{})
	var probes atomic.Int32
	var fallbackRouteSeen atomic.Bool
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(ctx context.Context) (int, error) {
			if probes.Add(1) == 1 {
				return 0, nil
			}
			close(finalProbeStarted)
			select {
			case <-releaseFinalProbe:
				return 0, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		},
		ProbeEvents: events,
		InspectFallback: func(context.Context, config.Config) (FallbackReport, error) {
			return FallbackReport{Reachable: true, TargetKeyFound: true}, nil
		},
		DebounceCount: 1,
		OnUpdate: func(snapshot Snapshot) {
			if snapshot.Route == Route1Password {
				fallbackRouteSeen.Store(true)
			}
		},
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	reconcileCtx, cancelReconcile := context.WithCancel(context.Background())
	defer cancelReconcile()
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- router.reconcile(reconcileCtx) }()
	select {
	case <-finalProbeStarted:
	case <-time.After(time.Second):
		t.Fatal("final device probe did not start")
	}
	close(events)
	close(releaseFinalProbe)
	select {
	case err := <-reconcileDone:
		if !errors.Is(err, ErrProbeEventsClosed) {
			t.Fatalf("closed event stream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconcile did not stop after event stream closed")
	}
	got := router.Current()
	if got.Route != RoutePIVFailClosed || got.ProbeState != ProbeUnavailable || got.FallbackChecked {
		t.Fatalf("closed event stream snapshot = %+v", got)
	}
	if fallbackRouteSeen.Load() {
		t.Fatal("router published fallback after device event stream closed")
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestRouterFailsClosedWhenEventStreamClosesDuringFallbackInspection(t *testing.T) {
	dir := tempDir(t)
	target := newPublicKey(t)
	cfg := routeConfig(dir, target)
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{keys: []*agent.Key{agentKey(target)}})
	events := make(chan struct{}, 1)
	inspectionStarted := make(chan struct{}, 1)
	inspectionCanceled := make(chan struct{}, 1)
	var count atomic.Int32
	count.Store(1)
	var fallbackRouteSeen atomic.Bool
	router := newGuardedRouter(dir, cfg, Options{
		Probe: func(context.Context) (int, error) {
			return int(count.Load()), nil
		},
		ProbeEvents: events,
		InspectFallback: func(ctx context.Context, _ config.Config) (FallbackReport, error) {
			inspectionStarted <- struct{}{}
			<-ctx.Done()
			inspectionCanceled <- struct{}{}
			return FallbackReport{}, ctx.Err()
		},
		PollInterval:  10 * time.Millisecond,
		ProbeTimeout:  time.Second,
		DebounceCount: 2,
		OnUpdate: func(snapshot Snapshot) {
			if snapshot.Route == Route1Password {
				fallbackRouteSeen.Store(true)
			}
		},
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})
	count.Store(0)
	events <- struct{}{}
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIVFailClosed && snapshot.ProbeState == ProbeNotDetected && !snapshot.FallbackChecked
	})
	select {
	case <-inspectionStarted:
	case <-time.After(time.Second):
		t.Fatal("fallback inspection did not start")
	}
	close(events)
	select {
	case err := <-done:
		if !errors.Is(err, ErrProbeEventsClosed) {
			t.Fatalf("closed event stream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("router did not stop after event stream closed during fallback inspection")
	}
	select {
	case <-inspectionCanceled:
	case <-time.After(time.Second):
		t.Fatal("fallback inspection was not canceled after event stream closed")
	}
	got := router.Current()
	if got.Route != RoutePIVFailClosed || got.ProbeState != ProbeUnavailable || got.FallbackChecked {
		t.Fatalf("closed event stream snapshot = %+v", got)
	}
	if fallbackRouteSeen.Load() {
		t.Fatal("router published fallback after device event stream closed")
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestRouterFailsClosedWhenDeviceEventStreamCloses(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	events := make(chan struct{})
	router := newGuardedRouter(dir, cfg, Options{
		Probe:       func(context.Context) (int, error) { return 1, nil },
		ProbeEvents: events,
	})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	waitForRouterSnapshot(t, router, func(snapshot Snapshot) bool {
		return snapshot.Route == RoutePIV && snapshot.ProbeState == ProbeConnected
	})
	close(events)
	select {
	case err := <-done:
		if !errors.Is(err, ErrProbeEventsClosed) {
			t.Fatalf("closed event stream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("router did not stop after device event stream closed")
	}
	got := router.Current()
	if got.Route != RoutePIVFailClosed || got.ProbeState != ProbeUnavailable || got.FallbackChecked {
		t.Fatalf("closed event stream snapshot = %+v", got)
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestAtomicRoutePreservesExistingConnections(t *testing.T) {
	dir := tempDir(t)
	first := filepath.Join(dir, "first.sock")
	second := filepath.Join(dir, "second.sock")
	serveLabelSocket(t, first, 'A')
	serveLabelSocket(t, second, 'B')
	public := filepath.Join(dir, "agent.sock")
	if err := atomicRoute(public, first); err != nil {
		t.Fatal(err)
	}
	old := dialLabelSocket(t, public, 'A')
	defer old.Close()
	if err := atomicRoute(public, second, first); err != nil {
		t.Fatal(err)
	}
	newConn := dialLabelSocket(t, public, 'B')
	_ = newConn.Close()
	if _, err := old.Write([]byte{'x'}); err != nil {
		t.Fatalf("old connection was interrupted: %v", err)
	}
	response := []byte{0}
	if _, err := old.Read(response); err != nil || response[0] != 'x' {
		t.Fatalf("old connection echo = %q, %v", response, err)
	}
}

func TestRouterRejectsUnmanagedPublicPath(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	if err := os.WriteFile(cfg.SocketPath, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	router := newGuardedRouter(dir, cfg, Options{Probe: func(context.Context) (int, error) { return 1, nil }})
	if err := router.Initialize(); err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("unmanaged public path error = %v", err)
	}
}

func TestRouterRecoversManagedSymlinkOnRestart(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.PIVSocketPath, &testAgent{})
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{})
	if err := atomicRoute(cfg.SocketPath, cfg.FallbackAgentSocket); err != nil {
		t.Fatal(err)
	}
	router := newGuardedRouter(dir, cfg, Options{Probe: func(context.Context) (int, error) { return 1, nil }})
	if err := router.Initialize(); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfg, RoutePIV)
}

func TestFailClosedBeforeStartRedirectsStaleFallbackWithoutPIV(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{})
	if err := atomicRoute(cfg.SocketPath, cfg.FallbackAgentSocket); err != nil {
		t.Fatal(err)
	}
	if err := FailClosedBeforeStart(cfg); err != nil {
		t.Fatal(err)
	}
	assertLinkTarget(t, cfg.SocketPath, cfg.PIVSocketPath)
	if socketReachable(cfg.SocketPath) {
		t.Fatal("stale fallback route remains reachable")
	}
}

func TestInspectPublicRouteRejectsFallbackManagedSocket(t *testing.T) {
	dir := tempDir(t)
	cfg := routeConfig(dir, newPublicKey(t))
	cfg.FallbackAgentSocket = cfg.BackendSocketPath
	serveAgent(t, cfg.FallbackAgentSocket, &testAgent{})
	if err := atomicRoute(cfg.SocketPath, cfg.FallbackAgentSocket); err != nil {
		t.Fatal(err)
	}
	report, err := InspectPublicRoute(cfg)
	if err == nil || !strings.Contains(err.Error(), "managed socket") {
		t.Fatalf("managed fallback report = %+v, error = %v", report, err)
	}
}

func TestInspectPublicRouteDoesNotClassifyEmptyFallback(t *testing.T) {
	dir := tempDir(t)
	if err := os.Symlink(".", filepath.Join(dir, "agent.sock")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	cfg := routeConfig(dir, newPublicKey(t))
	cfg.SocketPath = "agent.sock"
	cfg.FallbackAgentSocket = ""
	report, err := InspectPublicRoute(cfg)
	if err == nil || report.Route == Route1Password {
		t.Fatalf("empty fallback report = %+v, error = %v", report, err)
	}
}

func assertRoute(t *testing.T, cfg config.Config, want Route) {
	t.Helper()
	report, err := InspectPublicRoute(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.Route != want || !report.Managed || !report.TargetReachable {
		t.Fatalf("public route = %+v, want %q", report, want)
	}
}

func waitForRouterSnapshot(t *testing.T, router *Router, matches func(Snapshot) bool) Snapshot {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		snapshot := router.Current()
		if matches(snapshot) {
			return snapshot
		}
		if time.Now().After(deadline) {
			t.Fatalf("router snapshot did not reach expected state: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func routeConfig(dir string, target ssh.PublicKey) config.Config {
	return config.Config{
		SocketPath:          filepath.Join(dir, "agent.sock"),
		PIVSocketPath:       filepath.Join(dir, "piv-agent.sock"),
		BackendSocketPath:   filepath.Join(dir, "backend.sock"),
		FallbackAgent:       config.FallbackAgent1Password,
		FallbackAgentSocket: filepath.Join(dir, "fallback.sock"),
		PublicKey:           target,
	}
}

func newGuardedRouter(dir string, cfg config.Config, options Options) *Router {
	options.GuardPath = GuardPath(filepath.Join(dir, "config.json"))
	return New(cfg, options)
}

func newPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func agentKey(key ssh.PublicKey) *agent.Key {
	return &agent.Key{Format: key.Type(), Blob: key.Marshal(), Comment: "test"}
}

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "yubitouch-route-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type fileInfoWithoutStat struct {
	os.FileInfo
}

func (fileInfoWithoutStat) Sys() any { return nil }

func serveAgent(t *testing.T, path string, value agent.Agent) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = agent.ServeAgent(value, conn)
			}()
		}
	}()
}

func serveLabelSocket(t *testing.T, path string, label byte) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte{label})
				buffer := make([]byte, 1)
				for {
					n, readErr := conn.Read(buffer)
					if readErr != nil {
						return
					}
					_, _ = conn.Write(buffer[:n])
				}
			}()
		}
	}()
}

func dialLabelSocket(t *testing.T, path string, want byte) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	value := []byte{0}
	if _, err := conn.Read(value); err != nil || value[0] != want {
		conn.Close()
		t.Fatalf("socket label = %q, want %q, err=%v", value, []byte{want}, err)
	}
	return conn
}
