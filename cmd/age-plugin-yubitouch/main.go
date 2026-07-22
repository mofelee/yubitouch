package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/mofelee/yubitouch/internal/ageipc"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
)

const ageClientTimeoutMargin = 30 * time.Second

type configLoader func(string, string) (config.Config, error)
type clientFactory func(string, time.Duration) ageprofile.Client

type lazyAgeClient struct {
	home       string
	configPath string
	loadConfig configLoader
	newClient  clientFactory
}

var _ ageprofile.Client = (*lazyAgeClient)(nil)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p, err := plugin.New(ageprofile.PluginName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "age-plugin-yubitouch: initialize plugin")
		return 1
	}
	p.HandleRecipient(func(payload []byte) (age.Recipient, error) {
		return ageprofile.ParseRecipientPayload(payload)
	})
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintln(os.Stderr, "age-plugin-yubitouch: configuration is unavailable")
		return 1
	}
	configPath := config.PathFromEnvironment(home, os.Getenv)
	client := newLazyAgeClient(home, configPath)
	p.HandleIdentity(func(payload []byte) (age.Identity, error) {
		return ageprofile.ParseIdentityPayload(ctx, payload, client)
	})
	return p.Main()
}

func newLazyAgeClient(home, configPath string) *lazyAgeClient {
	return &lazyAgeClient{
		home:       home,
		configPath: configPath,
		loadConfig: config.Load,
		newClient: func(path string, timeout time.Duration) ageprofile.Client {
			return ageipc.NewClient(path, timeout)
		},
	}
}

func (c *lazyAgeClient) Unwrap(ctx context.Context, request ageprofile.UnwrapRequest) ([]byte, error) {
	if c == nil || c.loadConfig == nil || c.newClient == nil {
		return nil, &ageipc.Error{Class: ageipc.ClassInternal}
	}
	socketPath, timeout, ok := c.settings()
	if !ok {
		return nil, &ageipc.Error{Class: ageipc.ClassConfiguration}
	}
	client := c.newClient(socketPath, timeout)
	if client == nil {
		return nil, &ageipc.Error{Class: ageipc.ClassInternal}
	}
	return client.Unwrap(ctx, request)
}

func (c *lazyAgeClient) settings() (string, time.Duration, bool) {
	cfg, err := c.loadConfig(c.configPath, c.home)
	if err != nil || cfg.Age == nil {
		return "", 0, false
	}
	timeout, ok := ageClientTimeout(cfg.SignTimeout.Duration)
	if !ok {
		return "", 0, false
	}
	return cfg.AgeSocketPath, timeout, true
}

func ageClientTimeout(signTimeout time.Duration) (time.Duration, bool) {
	return config.SignTimeoutWithMargin(signTimeout, ageClientTimeoutMargin)
}
