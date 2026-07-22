package agentroute

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mofelee/yubitouch/internal/config"
)

type Route string

const (
	RoutePIV             Route = "piv"
	Route1Password       Route = "1password"
	RoutePIVFailClosed   Route = "piv_fail_closed"
	defaultProbeTimeout        = 5 * time.Second
	defaultPollInterval        = 2 * time.Second
	defaultDebounceCount       = 2
)

var (
	ErrProbeEventsRequired = errors.New("enabled fallback requires YubiKey events")
	ErrProbeEventsClosed   = errors.New("YubiKey event stream closed")
)

type ProbeState string

const (
	ProbeNotChecked  ProbeState = "not_checked"
	ProbeConnected   ProbeState = "connected"
	ProbeNotDetected ProbeState = "not_detected"
	ProbeUnavailable ProbeState = "probe_unavailable"
)

type Snapshot struct {
	Route             Route
	ProbeState        ProbeState
	FallbackChecked   bool
	FallbackReachable bool
	FallbackKeyFound  bool
	FallbackOtherKeys int
	ChangedAt         time.Time
	UpdatedAt         time.Time
}

type Options struct {
	Probe           func(context.Context) (int, error)
	ProbeEvents     <-chan struct{}
	InspectFallback func(context.Context, config.Config) (FallbackReport, error)
	PollInterval    time.Duration
	ProbeTimeout    time.Duration
	DebounceCount   int
	Now             func() time.Time
	OnUpdate        func(Snapshot)
	OnError         func(error)
	GuardPath       string
}

type Router struct {
	cfg             config.Config
	probe           func(context.Context) (int, error)
	probeEvents     <-chan struct{}
	inspectFallback func(context.Context, config.Config) (FallbackReport, error)
	pollInterval    time.Duration
	probeTimeout    time.Duration
	debounceCount   int
	now             func() time.Time
	onUpdate        func(Snapshot)
	onError         func(error)
	guardPath       string
	guardReady      bool

	mu        sync.RWMutex
	snapshot  Snapshot
	zeroCount int
}

func New(cfg config.Config, options Options) *Router {
	if options.PollInterval <= 0 {
		options.PollInterval = defaultPollInterval
	}
	if options.ProbeTimeout <= 0 {
		options.ProbeTimeout = defaultProbeTimeout
	}
	if options.DebounceCount <= 0 {
		options.DebounceCount = defaultDebounceCount
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.InspectFallback == nil {
		options.InspectFallback = InspectFallback
	}
	return &Router{
		cfg:             cfg,
		probe:           options.Probe,
		probeEvents:     options.ProbeEvents,
		inspectFallback: options.InspectFallback,
		pollInterval:    options.PollInterval,
		probeTimeout:    options.ProbeTimeout,
		debounceCount:   options.DebounceCount,
		now:             options.Now,
		onUpdate:        options.OnUpdate,
		onError:         options.OnError,
		guardPath:       options.GuardPath,
	}
}

func FailClosedBeforeStart(cfg config.Config) error {
	if cfg.FallbackAgentSocket == "" {
		return nil
	}
	info, err := os.Lstat(cfg.SocketPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 || !ownedByCurrentUser(info) {
		return nil
	}
	target, err := resolvedLinkTarget(cfg.SocketPath)
	if err != nil || target != filepath.Clean(cfg.FallbackAgentSocket) {
		return err
	}
	if safeFailClosedTarget(cfg.PIVSocketPath, cfg.FallbackAgentSocket) {
		return atomicRoute(cfg.SocketPath, cfg.PIVSocketPath, cfg.FallbackAgentSocket)
	}
	return removeRecordedFallback(cfg.SocketPath, cfg.FallbackAgentSocket)
}

func (r *Router) Initialize() error {
	if r.probe == nil {
		return errors.New("agent route requires a YubiKey probe")
	}
	if err := config.EnsurePrivateDir(filepath.Dir(r.cfg.SocketPath)); err != nil {
		return err
	}
	if err := validateSocket(r.cfg.PIVSocketPath); err != nil {
		return fmt.Errorf("PIV agent socket: %w", err)
	}
	if r.cfg.FallbackAgent == config.FallbackAgent1Password && r.guardPath == "" {
		return errors.New("enabled fallback requires a route guard path")
	}
	if r.guardPath != "" {
		if err := FailClosedFromGuard(r.guardPath); err != nil {
			return fmt.Errorf("fail closed from route guard: %w", err)
		}
		if err := FailClosedBeforeStart(r.cfg); err != nil {
			return fmt.Errorf("fail closed current fallback route: %w", err)
		}
		if err := persistGuard(r.guardPath, r.cfg); err != nil {
			return fmt.Errorf("persist route guard: %w", err)
		}
		r.guardReady = true
	}
	if err := r.validatePublicPath(); err != nil {
		return err
	}
	return r.setRoute(RoutePIVFailClosed, ProbeNotChecked, FallbackReport{}, false)
}

func (r *Router) Run(ctx context.Context) error {
	if r.cfg.FallbackAgent == config.FallbackAgent1Password && r.probeEvents == nil {
		return r.failUnavailable(ErrProbeEventsRequired)
	}
	retry := r.reconcileAndReport(ctx, false)
	var retryTimer *time.Timer
	var retryAt <-chan time.Time
	scheduleRetry := func(enabled bool) {
		if !enabled {
			if retryTimer != nil && !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			retryAt = nil
			return
		}
		if retryTimer == nil {
			retryTimer = time.NewTimer(r.pollInterval)
		} else {
			if !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			retryTimer.Reset(r.pollInterval)
		}
		retryAt = retryTimer.C
	}
	scheduleRetry(retry)
	defer func() {
		if retryTimer != nil {
			retryTimer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-r.probeEvents:
			if !ok {
				return r.failUnavailable(ErrProbeEventsClosed)
			}
			scheduleRetry(r.reconcileAndReport(ctx, false))
		case <-retryAt:
			retryAt = nil
			scheduleRetry(r.reconcileAndReport(ctx, true))
		}
	}
}

func (r *Router) failUnavailable(err error) error {
	r.zeroCount = 0
	err = errors.Join(err, r.setRoute(RoutePIVFailClosed, ProbeUnavailable, FallbackReport{}, false))
	r.reportError(err)
	return err
}

func (r *Router) reconcileAndReport(ctx context.Context, advanceDebounce bool) bool {
	err := r.reconcileWithDebounce(ctx, advanceDebounce)
	if err != nil {
		r.reportError(err)
		return true
	}
	probeState := r.Current().ProbeState
	return probeState == ProbeNotDetected || probeState == ProbeUnavailable
}

func (r *Router) Current() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot
}

func (r *Router) FailClosed() error {
	r.zeroCount = 0
	return r.setRoute(RoutePIVFailClosed, ProbeNotChecked, FallbackReport{}, false)
}

func (r *Router) reconcile(ctx context.Context) error {
	return r.reconcileWithDebounce(ctx, true)
}

func (r *Router) reconcileWithDebounce(ctx context.Context, advanceDebounce bool) error {
	if r.cfg.FallbackAgent != config.FallbackAgent1Password {
		r.zeroCount = 0
		return r.setRoute(RoutePIV, ProbeNotChecked, FallbackReport{}, false)
	}
	probeCtx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	count, err := r.probe(probeCtx)
	cancel()
	if err != nil {
		r.zeroCount = 0
		return r.setRoute(RoutePIVFailClosed, ProbeUnavailable, FallbackReport{}, false)
	}
	if count > 0 {
		r.zeroCount = 0
		return r.setRoute(RoutePIV, ProbeConnected, FallbackReport{}, false)
	}
	if r.zeroCount == 0 {
		r.zeroCount = 1
	} else if advanceDebounce && r.zeroCount < r.debounceCount {
		r.zeroCount++
	}
	if r.zeroCount < r.debounceCount {
		return r.setRoute(RoutePIVFailClosed, ProbeNotDetected, FallbackReport{}, false)
	}
	report, fallbackErr, interrupted, eventsClosed := r.inspectFallbackWhileWatching(ctx)
	if eventsClosed {
		r.zeroCount = 0
		return errors.Join(ErrProbeEventsClosed, r.setRoute(RoutePIVFailClosed, ProbeUnavailable, FallbackReport{}, false))
	}
	if interrupted {
		return r.reconcileProbeEvent(ctx)
	}
	if fallbackErr != nil || !report.Reachable || !report.TargetKeyFound || report.OtherKeys != 0 {
		return r.setRoute(RoutePIVFailClosed, ProbeNotDetected, report, true)
	}
	// Fallback inspection can wait on another agent. Recheck the cached USB state
	// before publishing that route so a reinsert during the inspection wins.
	recheckCtx, recheckCancel := context.WithTimeout(ctx, r.probeTimeout)
	count, err = r.probe(recheckCtx)
	recheckCancel()
	if err != nil {
		r.zeroCount = 0
		return r.setRoute(RoutePIVFailClosed, ProbeUnavailable, FallbackReport{}, false)
	}
	if count > 0 {
		r.zeroCount = 0
		return r.setRoute(RoutePIV, ProbeConnected, FallbackReport{}, false)
	}
	if interrupted, eventsClosed := r.consumePendingProbeEvent(); eventsClosed {
		r.zeroCount = 0
		return errors.Join(ErrProbeEventsClosed, r.setRoute(RoutePIVFailClosed, ProbeUnavailable, FallbackReport{}, false))
	} else if interrupted {
		return r.reconcileProbeEvent(ctx)
	}
	return r.setRoute(Route1Password, ProbeNotDetected, report, true)
}

type fallbackInspectionResult struct {
	report FallbackReport
	err    error
}

func (r *Router) inspectFallbackWhileWatching(ctx context.Context) (FallbackReport, error, bool, bool) {
	fallbackCtx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	defer cancel()
	result := make(chan fallbackInspectionResult, 1)
	go func() {
		report, err := r.inspectFallback(fallbackCtx, r.cfg)
		result <- fallbackInspectionResult{report: report, err: err}
	}()
	select {
	case got := <-result:
		if interrupted, eventsClosed := r.consumePendingProbeEvent(); interrupted || eventsClosed {
			return FallbackReport{}, nil, interrupted, eventsClosed
		}
		return got.report, got.err, false, false
	case _, ok := <-r.probeEvents:
		return FallbackReport{}, nil, ok, !ok
	case <-fallbackCtx.Done():
		return FallbackReport{}, fallbackCtx.Err(), false, false
	}
}

func (r *Router) consumePendingProbeEvent() (interrupted bool, eventsClosed bool) {
	select {
	case _, ok := <-r.probeEvents:
		return ok, !ok
	default:
		return false, false
	}
}

func (r *Router) reconcileProbeEvent(ctx context.Context) error {
	probeCtx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	count, err := r.probe(probeCtx)
	cancel()
	if err != nil {
		r.zeroCount = 0
		return r.setRoute(RoutePIVFailClosed, ProbeUnavailable, FallbackReport{}, false)
	}
	if count > 0 {
		r.zeroCount = 0
		return r.setRoute(RoutePIV, ProbeConnected, FallbackReport{}, false)
	}
	if r.zeroCount == 0 {
		r.zeroCount = 1
	}
	return r.setRoute(RoutePIVFailClosed, ProbeNotDetected, FallbackReport{}, false)
}

func (r *Router) setRoute(route Route, probe ProbeState, fallback FallbackReport, fallbackChecked bool) error {
	if route == Route1Password {
		if r.cfg.FallbackAgent != config.FallbackAgent1Password {
			return errors.New("1Password fallback is not enabled")
		}
		if !r.guardReady {
			return errors.New("1Password fallback route guard is not ready")
		}
	}
	target := r.cfg.PIVSocketPath
	if route == Route1Password {
		target = r.cfg.FallbackAgentSocket
	}
	managed := []string{r.cfg.BackendSocketPath}
	if route == Route1Password {
		managed = []string{r.cfg.PIVSocketPath, r.cfg.BackendSocketPath}
	} else if r.cfg.FallbackAgentSocket != "" {
		managed = append(managed, r.cfg.FallbackAgentSocket)
	}
	if err := validateSocket(target, managed...); err != nil {
		if route != Route1Password {
			r.removeFallbackRoute()
		}
		return fmt.Errorf("route target is unsafe: %w", err)
	}
	if route == Route1Password {
		if err := ValidateGuard(r.guardPath, r.cfg); err != nil {
			guardErr := fmt.Errorf("1Password fallback route guard is invalid: %w", err)
			failClosedErr := r.setRoute(RoutePIVFailClosed, probe, fallback, fallbackChecked)
			return errors.Join(guardErr, failClosedErr)
		}
	}
	if err := atomicRoute(r.cfg.SocketPath, target, r.managedRouteTargets()...); err != nil {
		if route == Route1Password {
			failClosedErr := r.setRoute(RoutePIVFailClosed, probe, fallback, fallbackChecked)
			return errors.Join(err, failClosedErr)
		}
		r.removeFallbackRoute()
		return err
	}

	now := r.now().UTC()
	r.mu.Lock()
	previous := r.snapshot
	changedAt := previous.ChangedAt
	if previous.Route != route || changedAt.IsZero() {
		changedAt = now
	}
	next := Snapshot{
		Route:             route,
		ProbeState:        probe,
		FallbackChecked:   fallbackChecked,
		FallbackReachable: fallback.Reachable,
		FallbackKeyFound:  fallback.TargetKeyFound,
		FallbackOtherKeys: fallback.OtherKeys,
		ChangedAt:         changedAt,
		UpdatedAt:         now,
	}
	r.snapshot = next
	r.mu.Unlock()
	if r.onUpdate != nil && snapshotChanged(previous, next) {
		r.onUpdate(next)
	}
	return nil
}

func (r *Router) validatePublicPath() error {
	info, err := os.Lstat(r.cfg.SocketPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ownedByCurrentUser(info) {
		return errors.New("public agent path is not owned by the current user")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, readErr := resolvedLinkTarget(r.cfg.SocketPath)
		if readErr != nil {
			return readErr
		}
		isPIV := r.cfg.PIVSocketPath != "" && target == filepath.Clean(r.cfg.PIVSocketPath)
		isStaleFallback := r.cfg.FallbackAgentSocket != "" && target == filepath.Clean(r.cfg.FallbackAgentSocket)
		if !isPIV && !isStaleFallback {
			return errors.New("public agent symlink is not managed by YubiTouch")
		}
		return nil
	}
	if info.Mode()&os.ModeSocket != 0 {
		if socketReachable(r.cfg.SocketPath) {
			return errors.New("an unmanaged agent is already listening at the public path")
		}
		return nil
	}
	return errors.New("refusing to replace a non-socket public agent path")
}

func (r *Router) removeFallbackRoute() {
	if r.cfg.FallbackAgentSocket == "" {
		return
	}
	target, err := resolvedLinkTarget(r.cfg.SocketPath)
	if err == nil && target == filepath.Clean(r.cfg.FallbackAgentSocket) {
		_ = removeRecordedFallback(r.cfg.SocketPath, r.cfg.FallbackAgentSocket)
	}
}

func (r *Router) managedRouteTargets() []string {
	targets := []string{r.cfg.PIVSocketPath}
	if r.cfg.FallbackAgentSocket != "" {
		targets = append(targets, r.cfg.FallbackAgentSocket)
	}
	return targets
}

func atomicRoute(publicPath string, target string, allowedCurrentTargets ...string) error {
	return atomicRouteWithHook(publicPath, target, allowedCurrentTargets, nil)
}

func atomicRouteWithHook(publicPath string, target string, allowedCurrentTargets []string, beforeCommit func()) error {
	if target == "" || !filepath.IsAbs(target) {
		return errors.New("route target must be an absolute path")
	}
	allowed := normalizedTargets(append(append([]string(nil), allowedCurrentTargets...), target))
	initial, err := inspectReplaceableRoutePath(publicPath, allowed)
	if err != nil {
		return err
	}
	if initial.kind == routePathSymlink && initial.target == filepath.Clean(target) {
		return nil
	}
	temp, err := os.CreateTemp(filepath.Dir(publicPath), ".agent-route-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Remove(tempPath); err != nil {
		return err
	}
	defer os.Remove(tempPath)
	if err := os.Symlink(filepath.Clean(target), tempPath); err != nil {
		return err
	}
	if beforeCommit != nil {
		beforeCommit()
	}
	if err := revalidateRoutePath(publicPath, initial, allowed); err != nil {
		return err
	}
	if err := os.Rename(tempPath, publicPath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(publicPath))
}

type routePathKind uint8

const (
	routePathMissing routePathKind = iota
	routePathSymlink
	routePathStaleSocket
)

type routePathState struct {
	kind   routePathKind
	target string
	info   fs.FileInfo
}

func inspectReplaceableRoutePath(path string, allowedTargets map[string]struct{}) (routePathState, error) {
	if path == "" {
		return routePathState{}, errors.New("public agent path is empty")
	}
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return routePathState{}, fmt.Errorf("public agent parent: %w", err)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return routePathState{kind: routePathMissing}, nil
	}
	if err != nil {
		return routePathState{}, err
	}
	if !ownedByCurrentUser(info) {
		return routePathState{}, errors.New("public agent path is not owned by the current user")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := resolvedLinkTarget(path)
		if err != nil {
			return routePathState{}, err
		}
		if _, ok := allowedTargets[target]; !ok {
			return routePathState{}, errors.New("public agent symlink target is not managed")
		}
		return routePathState{kind: routePathSymlink, target: target, info: info}, nil
	}
	if info.Mode()&os.ModeSocket != 0 && !socketReachable(path) {
		return routePathState{kind: routePathStaleSocket, info: info}, nil
	}
	return routePathState{}, errors.New("public agent path is not replaceable")
}

func revalidateRoutePath(path string, initial routePathState, allowedTargets map[string]struct{}) error {
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("public agent parent changed: %w", err)
	}
	info, err := os.Lstat(path)
	switch initial.kind {
	case routePathMissing:
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("public agent path appeared during route update")
	case routePathSymlink:
		if err != nil {
			return errors.New("public agent path changed during route update")
		}
		if info.Mode()&os.ModeSymlink == 0 || !ownedByCurrentUser(info) {
			return errors.New("public agent path became unmanaged during route update")
		}
		target, readErr := resolvedLinkTarget(path)
		if readErr != nil {
			return readErr
		}
		if _, ok := allowedTargets[target]; !ok {
			return errors.New("public agent symlink became unmanaged during route update")
		}
		return nil
	case routePathStaleSocket:
		if err != nil || info.Mode()&os.ModeSocket == 0 || !ownedByCurrentUser(info) || !os.SameFile(initial.info, info) || socketReachable(path) {
			return errors.New("stale public agent socket changed during route update")
		}
		return nil
	default:
		return errors.New("invalid public agent route state")
	}
}

func normalizedTargets(paths []string) map[string]struct{} {
	targets := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path != "" {
			targets[filepath.Clean(path)] = struct{}{}
		}
	}
	return targets
}

type PublicRouteReport struct {
	Managed         bool
	Route           Route
	TargetReachable bool
}

func InspectPublicRoute(cfg config.Config) (PublicRouteReport, error) {
	info, err := os.Lstat(cfg.SocketPath)
	if err != nil {
		return PublicRouteReport{}, err
	}
	if info.Mode()&os.ModeSymlink == 0 || !ownedByCurrentUser(info) {
		return PublicRouteReport{}, errors.New("public agent path is not a current-user YubiTouch symlink")
	}
	target, err := resolvedLinkTarget(cfg.SocketPath)
	if err != nil {
		return PublicRouteReport{}, err
	}
	report := PublicRouteReport{Managed: true}
	pivTarget := ""
	if cfg.PIVSocketPath != "" {
		pivTarget = filepath.Clean(cfg.PIVSocketPath)
	}
	fallbackTarget := ""
	if cfg.FallbackAgentSocket != "" {
		fallbackTarget = filepath.Clean(cfg.FallbackAgentSocket)
	}
	switch {
	case pivTarget != "" && target == pivTarget:
		report.Route = RoutePIV
		managed := []string{cfg.BackendSocketPath}
		if cfg.FallbackAgentSocket != "" {
			managed = append(managed, cfg.FallbackAgentSocket)
		}
		if err := validateSocket(target, managed...); err != nil {
			return report, err
		}
	case cfg.FallbackAgent == config.FallbackAgent1Password && fallbackTarget != "" && target == fallbackTarget:
		report.Route = Route1Password
		if err := validateSocket(target, cfg.PIVSocketPath, cfg.BackendSocketPath); err != nil {
			return report, err
		}
	default:
		return PublicRouteReport{}, errors.New("public agent symlink target is not configured")
	}
	report.TargetReachable = socketReachable(cfg.SocketPath)
	return report, nil
}

func (r *Router) reportError(err error) {
	if r.onError != nil {
		r.onError(err)
	}
}

func resolvedLinkTarget(path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return filepath.Clean(target), nil
}

func socketReachable(path string) bool {
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func snapshotChanged(left Snapshot, right Snapshot) bool {
	return left.Route != right.Route ||
		left.ProbeState != right.ProbeState ||
		left.FallbackChecked != right.FallbackChecked ||
		left.FallbackReachable != right.FallbackReachable ||
		left.FallbackKeyFound != right.FallbackKeyFound ||
		left.FallbackOtherKeys != right.FallbackOtherKeys
}
