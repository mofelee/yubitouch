package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mofelee/yubitouch/internal/agehelper"
	"github.com/mofelee/yubitouch/internal/ageipc"
	"github.com/mofelee/yubitouch/internal/agentproxy"
	"github.com/mofelee/yubitouch/internal/agentroute"
	"github.com/mofelee/yubitouch/internal/ageprobe"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/ageservice"
	"github.com/mofelee/yubitouch/internal/backend"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/diagnostic"
	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/internal/state"
	"github.com/mofelee/yubitouch/internal/system"
	"github.com/mofelee/yubitouch/internal/ui"
)

type Options struct {
	ConfigPath  string
	Home        string
	Executable  string
	Application Application
}

type Application interface {
	signing.Sink
	Run(context.Context, <-chan error) error
}

func Run(ctx context.Context, options Options) error {
	guardPath := agentroute.GuardPath(options.ConfigPath)
	if err := agentroute.FailClosedFromGuard(guardPath); err != nil {
		return fmt.Errorf("fail closed from route guard: %w", err)
	}
	cfg, err := config.Load(options.ConfigPath, options.Home)
	if err != nil {
		return err
	}
	var ageRequestTimeout time.Duration
	if cfg.Age != nil {
		var ok bool
		ageRequestTimeout, ok = config.SignTimeoutWithMargin(cfg.SignTimeout.Duration, 10*time.Second)
		if !ok {
			return errors.New("invalid sign_timeout")
		}
	}
	if err := agentroute.FailClosedBeforeStart(cfg); err != nil {
		return fmt.Errorf("fail closed before daemon start: %w", err)
	}
	logger, err := diagnostic.Open(diagnostic.Path(options.ConfigPath), cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("open diagnostic log: %w", err)
	}
	defer logger.Close()
	_ = logger.Write(diagnostic.LevelInfo, diagnostic.EventDaemonStarted, diagnostic.FailureNone)

	deps, err := system.Resolve(cfg)
	if err != nil {
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return err
	}
	deviceProbe := system.ProbeYubiKeys
	var deviceMonitor *system.YubiKeyMonitor
	if cfg.FallbackAgent == config.FallbackAgent1Password {
		deviceMonitor, err = system.NewYubiKeyMonitor()
		if err != nil {
			_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
			return fmt.Errorf("start YubiKey monitor: %w", err)
		}
		defer deviceMonitor.Close()
		deviceProbe = deviceMonitor.Probe
	}
	manager := backend.New(cfg, deps, options.Executable, options.ConfigPath)
	manager.SetDeviceProbe(deviceProbe)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = manager.Stop(stopCtx)
	}()

	store := state.NewStore(filepath.Join(filepath.Dir(options.ConfigPath), "state.json"))
	if err := store.Initialize(); err != nil {
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return fmt.Errorf("initialize state: %w", err)
	}
	defer store.Remove()

	listener, err := agentproxy.Listen(cfg.PIVSocketPath)
	if err != nil {
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return err
	}
	_ = logger.Write(diagnostic.LevelInfo, diagnostic.EventProxyListening, diagnostic.FailureNone)
	var ageListener net.Listener
	if cfg.Age != nil {
		ageListener, err = ageipc.Listen(cfg.AgeSocketPath)
		if err != nil {
			_ = listener.Close()
			_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
			return err
		}
		_ = logger.Write(diagnostic.LevelInfo, diagnostic.EventAgeIPCListening, diagnostic.FailureNone)
	}
	var probeEvents <-chan struct{}
	if deviceMonitor != nil {
		probeEvents = deviceMonitor.Events()
	}
	router := agentroute.New(cfg, agentroute.Options{
		Probe:       deviceProbe,
		ProbeEvents: probeEvents,
		GuardPath:   guardPath,
		OnError: func(err error) {
			_ = logger.Write(diagnostic.LevelError, diagnostic.EventRouteFailClosed, diagnostic.Classify(err))
		},
		OnUpdate: func(snapshot agentroute.Snapshot) {
			store.SetRoute(snapshot)
			event := diagnostic.EventRoutePIV
			switch snapshot.Route {
			case agentroute.Route1Password:
				event = diagnostic.EventRoute1Password
			case agentroute.RoutePIVFailClosed:
				event = diagnostic.EventRouteFailClosed
			}
			_ = logger.Write(diagnostic.LevelInfo, event, diagnostic.FailureNone)
		},
	})
	if err := router.Initialize(); err != nil {
		_ = router.FailClosed()
		_ = listener.Close()
		if ageListener != nil {
			_ = ageListener.Close()
		}
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return fmt.Errorf("initialize agent route: %w", err)
	}
	var routerService, serverService, ageServerService *backgroundService
	shutdownComplete := false
	defer func() {
		if shutdownComplete {
			return
		}
		_ = shutdownServices(
			routerService,
			router.FailClosed,
			serverService,
			ageServerService,
			listenerCloser(listener),
			listenerCloser(ageListener),
		)
	}()

	app := options.Application
	if app == nil {
		app = ui.New(cfg.Sound)
	}
	coordinator := signing.New(manager, ui.MultiSink{store, app, diagnostic.NewSigningSink(logger)}, cfg.SignTimeout.Duration)
	if cancelable, ok := app.(interface{ SetCancelHandler(func(uint64) bool) }); ok {
		cancelable.SetCancelHandler(coordinator.Cancel)
	}
	server := &agentproxy.Server{
		TargetKey:      cfg.PublicKey,
		Comment:        "YubiTouch PIV 9A",
		BackendFactory: manager.Connect,
		Coordinator:    coordinator,
	}
	serviceCount := 2
	if ageListener != nil {
		serviceCount++
	}
	serviceResult := make(chan error, serviceCount)
	serviceParent := context.WithoutCancel(ctx)
	serverService = startBackgroundService(serviceParent, serviceResult, func(ctx context.Context) error {
		return server.Serve(ctx, listener)
	})
	routerService = startBackgroundService(serviceParent, serviceResult, router.Run)
	if ageListener != nil {
		publicProbe := ageprobe.NewRunner(options.Executable, options.ConfigPath, 5*time.Second)
		ageService := ageservice.New(ageservice.Options{
			Config:      cfg,
			Probe:       publicProbe,
			Coordinator: coordinator,
			NewRunner: func(path ageprofile.Path) ageservice.Runner {
				mode := agehelper.ModeHardware
				if path == ageprofile.PathRecovery {
					mode = agehelper.ModeRecovery
				}
				return &ageRunner{
					mode:   mode,
					runner: agehelper.NewRunner(options.Executable, options.ConfigPath, cfg.SignTimeout.Duration),
				}
			},
			Sink: ageSink{store, diagnostic.NewAgeSink(logger)},
		})
		ageServer := &ageipc.Server{
			Handler:        ageService,
			MaxConcurrent:  4,
			RequestTimeout: ageRequestTimeout,
		}
		ageServerService = startBackgroundService(serviceParent, serviceResult, func(ctx context.Context) error {
			return ageServer.Serve(ctx, ageListener)
		})
	}
	err = app.Run(ctx, serviceResult)
	shutdownErr := shutdownServices(
		routerService,
		router.FailClosed,
		serverService,
		ageServerService,
		listenerCloser(listener),
		listenerCloser(ageListener),
	)
	shutdownComplete = true
	err = errors.Join(err, shutdownErr)
	if err != nil {
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return err
	}
	_ = logger.Write(diagnostic.LevelInfo, diagnostic.EventDaemonStopped, diagnostic.FailureNone)
	return nil
}

type ageRunner struct {
	mode   agehelper.Mode
	runner *agehelper.Runner
	call   *agehelper.Call
}

func (r *ageRunner) Start(ctx context.Context, envelope ageprofile.Envelope) ageipc.ErrorClass {
	if r == nil || r.runner == nil || r.call != nil {
		return ageipc.ClassInternal
	}
	call, err := r.runner.Start(ctx, r.mode, agehelper.Request{Envelope: envelope})
	if err != nil {
		return mapHelperError(r.mode, agehelper.ErrorClassOf(err))
	}
	r.call = call
	return ""
}

func (r *ageRunner) WaitReady() ageipc.ErrorClass {
	if r == nil || r.mode != agehelper.ModeHardware || r.call == nil {
		return ageipc.ClassInternal
	}
	if err := r.call.WaitReady(); err != nil {
		r.call = nil
		return mapHelperError(r.mode, agehelper.ErrorClassOf(err))
	}
	return ""
}

func (r *ageRunner) Wait() ([]byte, ageipc.ErrorClass) {
	if r == nil || r.call == nil {
		return nil, ageipc.ClassInternal
	}
	call := r.call
	r.call = nil
	var fileKey []byte
	var err error
	if r.mode == agehelper.ModeHardware {
		fileKey, err = call.ContinueAndWait()
	} else {
		fileKey, err = call.Wait()
	}
	if err != nil {
		agehelper.ClearSecret(fileKey)
		return nil, mapHelperError(r.mode, agehelper.ErrorClassOf(err))
	}
	if len(fileKey) != 16 {
		agehelper.ClearSecret(fileKey)
		return nil, helperFailureClass(r.mode)
	}
	result := append([]byte(nil), fileKey...)
	agehelper.ClearSecret(fileKey)
	return result, ""
}

func (r *ageRunner) CancelCurrent() {
	if r != nil && r.runner != nil {
		r.runner.CancelCurrent()
	}
}

func mapHelperError(mode agehelper.Mode, class agehelper.ErrorClass) ageipc.ErrorClass {
	switch class {
	case agehelper.ErrorInvalidRequest:
		return ageipc.ClassInvalidRequest
	case agehelper.ErrorConfiguration:
		return ageipc.ClassConfiguration
	case agehelper.ErrorPINProvider, agehelper.ErrorHardwarePIN:
		return ageipc.ClassPINFailed
	case agehelper.ErrorHardwareMismatch:
		return ageipc.ClassTargetMismatch
	case agehelper.ErrorHardware:
		return ageipc.ClassHardwareFailed
	case agehelper.ErrorRecoveryUnavailable:
		return ageipc.ClassRecoveryUnavailable
	case agehelper.ErrorRecoveryMismatch:
		return ageipc.ClassRecoveryFailed
	case agehelper.ErrorCanceled:
		return ageipc.ClassCanceled
	case agehelper.ErrorTimeout:
		return ageipc.ClassTimeout
	case agehelper.ErrorUnwrap, agehelper.ErrorHelper:
		return helperFailureClass(mode)
	default:
		return ageipc.ClassInternal
	}
}

func helperFailureClass(mode agehelper.Mode) ageipc.ErrorClass {
	if mode == agehelper.ModeRecovery {
		return ageipc.ClassRecoveryFailed
	}
	return ageipc.ClassHardwareFailed
}

type ageSink []ageservice.Sink

func (s ageSink) HandleAge(event ageservice.Event) {
	for _, sink := range s {
		if sink != nil {
			sink.HandleAge(event)
		}
	}
}

type backgroundService struct {
	cancel context.CancelFunc
	done   <-chan struct{}
}

func startBackgroundService(
	parent context.Context,
	result chan<- error,
	run func(context.Context) error,
) *backgroundService {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- run(ctx)
	}()
	return &backgroundService{cancel: cancel, done: done}
}

func (s *backgroundService) stop() {
	s.requestStop()
	s.wait()
}

func (s *backgroundService) requestStop() {
	if s == nil {
		return
	}
	s.cancel()
}

func (s *backgroundService) wait() {
	if s == nil {
		return
	}
	<-s.done
}

func shutdownServices(
	router *backgroundService,
	failClosed func() error,
	server *backgroundService,
	ageServer *backgroundService,
	closeListener func() error,
	closeAgeListener func() error,
) error {
	router.stop()
	routeErr := failClosed()
	// Cancel queued age work before releasing an active SSH operation from the
	// shared PIV coordinator. No new PIN, UI, or helper work may start during shutdown.
	ageServer.requestStop()
	server.requestStop()
	ageServer.wait()
	server.wait()
	return errors.Join(routeErr, closeListener(), closeAgeListener())
}

func listenerCloser(listener net.Listener) func() error {
	if listener == nil {
		return func() error { return nil }
	}
	return func() error {
		err := listener.Close()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func OptionsFromOS(configPath string, home string) (Options, error) {
	executable, err := os.Executable()
	if err != nil {
		return Options{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return Options{}, err
	}
	return Options{ConfigPath: configPath, Home: home, Executable: executable}, nil
}
