package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mofelee/yubitouch/internal/agentproxy"
	"github.com/mofelee/yubitouch/internal/agentroute"
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
	manager := backend.New(cfg, deps, options.Executable, options.ConfigPath)
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
	router := agentroute.New(cfg, agentroute.Options{
		Probe:     system.ProbeYubiKeys,
		GuardPath: guardPath,
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
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return fmt.Errorf("initialize agent route: %w", err)
	}
	var routerService, serverService *backgroundService
	shutdownComplete := false
	defer func() {
		if shutdownComplete {
			return
		}
		if routerService != nil {
			routerService.stop()
		}
		_ = router.FailClosed()
		if serverService != nil {
			serverService.stop()
		}
		_ = listener.Close()
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
	serviceResult := make(chan error, 2)
	serviceParent := context.WithoutCancel(ctx)
	serverService = startBackgroundService(serviceParent, serviceResult, func(ctx context.Context) error {
		return server.Serve(ctx, listener)
	})
	routerService = startBackgroundService(serviceParent, serviceResult, router.Run)
	err = app.Run(ctx, serviceResult)
	shutdownErr := shutdownServices(routerService, router.FailClosed, serverService, listener.Close)
	shutdownComplete = true
	err = errors.Join(err, shutdownErr)
	if err != nil {
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return err
	}
	_ = logger.Write(diagnostic.LevelInfo, diagnostic.EventDaemonStopped, diagnostic.FailureNone)
	return nil
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
	s.cancel()
	<-s.done
}

func shutdownServices(
	router *backgroundService,
	failClosed func() error,
	server *backgroundService,
	closeListener func() error,
) error {
	router.stop()
	routeErr := failClosed()
	server.stop()
	return errors.Join(routeErr, closeListener())
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
