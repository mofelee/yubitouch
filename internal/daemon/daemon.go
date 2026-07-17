package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mofelee/yubitouch/internal/agentproxy"
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
	cfg, err := config.Load(options.ConfigPath, options.Home)
	if err != nil {
		return err
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

	listener, err := agentproxy.Listen(cfg.SocketPath)
	if err != nil {
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return err
	}
	defer listener.Close()
	_ = logger.Write(diagnostic.LevelInfo, diagnostic.EventProxyListening, diagnostic.FailureNone)

	app := options.Application
	if app == nil {
		app = ui.New(cfg.Sound)
	}
	coordinator := signing.New(manager, ui.MultiSink{store, app, diagnostic.NewSigningSink(logger)}, cfg.SignTimeout.Duration)
	server := &agentproxy.Server{
		TargetKey:      cfg.PublicKey,
		Comment:        "YubiTouch PIV 9A",
		BackendFactory: manager.Connect,
		Coordinator:    coordinator,
	}
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(ctx, listener) }()
	err = app.Run(ctx, serverResult)
	if err != nil {
		_ = logger.Write(diagnostic.LevelError, diagnostic.EventDaemonFailed, diagnostic.Classify(err))
		return err
	}
	_ = logger.Write(diagnostic.LevelInfo, diagnostic.EventDaemonStopped, diagnostic.FailureNone)
	return nil
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
