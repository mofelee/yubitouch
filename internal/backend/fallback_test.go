package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/agentproxy"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/internal/system"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type fallbackTestAgent struct {
	keys           []*agent.Key
	listCount      atomic.Int32
	signCount      atomic.Int32
	extensionCount atomic.Int32
	listStarted    chan struct{}
	listRelease    chan struct{}
	listOnce       sync.Once
}

func (a *fallbackTestAgent) List() ([]*agent.Key, error) {
	a.listCount.Add(1)
	if a.listStarted != nil {
		a.listOnce.Do(func() { close(a.listStarted) })
		<-a.listRelease
	}
	result := make([]*agent.Key, len(a.keys))
	for i, key := range a.keys {
		result[i] = &agent.Key{Format: key.Format, Blob: append([]byte(nil), key.Blob...), Comment: key.Comment}
	}
	return result, nil
}

func (a *fallbackTestAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *fallbackTestAgent) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	a.signCount.Add(1)
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, ed25519.SignatureSize)}, nil
}

func (a *fallbackTestAgent) Add(agent.AddedKey) error       { return errors.New("disabled") }
func (a *fallbackTestAgent) Remove(ssh.PublicKey) error     { return errors.New("disabled") }
func (a *fallbackTestAgent) RemoveAll() error               { return errors.New("disabled") }
func (a *fallbackTestAgent) Lock([]byte) error              { return errors.New("disabled") }
func (a *fallbackTestAgent) Unlock([]byte) error            { return errors.New("disabled") }
func (a *fallbackTestAgent) Signers() ([]ssh.Signer, error) { return nil, errors.New("disabled") }

func (a *fallbackTestAgent) Extension(string, []byte) ([]byte, error) {
	a.extensionCount.Add(1)
	return []byte{6}, nil
}

func TestFallbackFiltersAllNonTargetKeys(t *testing.T) {
	target := fallbackPublicKey(t)
	other := fallbackPublicKey(t)
	fake := &fallbackTestAgent{keys: []*agent.Key{agentKey(other), agentKey(target)}}
	socket := serveFallbackAgent(t, fake)
	cfg := fallbackConfig(target, socket)

	report, err := InspectFallback(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Reachable || !report.TargetKeyFound || report.OtherKeys != 1 {
		t.Fatalf("fallback report = %+v", report)
	}

	client, err := connectFallback(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !bytes.Equal(keys[0].Blob, target.Marshal()) {
		t.Fatalf("filtered identities = %+v", keys)
	}
	if _, err := client.Sign(other, []byte("not allowed")); !errors.Is(err, agentproxy.ErrKeyNotAllowed) {
		t.Fatalf("other key sign error = %v", err)
	}
	if _, err := client.Sign(target, []byte("allowed")); err != nil {
		t.Fatal(err)
	}
	if fake.signCount.Load() != 1 {
		t.Fatalf("fallback sign count = %d", fake.signCount.Load())
	}
}

func TestFallbackFailsClosedWhenTargetKeyIsMissing(t *testing.T) {
	target := fallbackPublicKey(t)
	fake := &fallbackTestAgent{keys: []*agent.Key{agentKey(fallbackPublicKey(t)), agentKey(fallbackPublicKey(t))}}
	cfg := fallbackConfig(target, serveFallbackAgent(t, fake))
	report, err := InspectFallback(context.Background(), cfg)
	if !errors.Is(err, signing.ErrFallbackKeyUnavailable) {
		t.Fatalf("fallback error = %v", err)
	}
	if !report.Reachable || report.TargetKeyFound || report.OtherKeys != 2 {
		t.Fatalf("fallback report = %+v", report)
	}
}

func TestManagerSelectsFallbackOnlyForDefiniteMissingDevice(t *testing.T) {
	target := fallbackPublicKey(t)
	fake := &fallbackTestAgent{keys: []*agent.Key{agentKey(target)}}
	cfg := fallbackConfig(target, serveFallbackAgent(t, fake))
	manager := New(cfg, systemDependenciesForFallback(), "/bin/false", "/tmp/config.json")
	var primaryCalls atomic.Int32
	primaryErr := errors.New("primary path selected")
	manager.ensurePrimary = func(context.Context) error {
		primaryCalls.Add(1)
		return primaryErr
	}

	manager.probeKeys = func(context.Context) (int, error) { return 0, nil }
	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentSigner() != signing.Signer1Password || primaryCalls.Load() != 0 || fake.listCount.Load() != 1 {
		t.Fatalf("missing route signer=%q primary=%d lists=%d", manager.CurrentSigner(), primaryCalls.Load(), fake.listCount.Load())
	}

	for name, probe := range map[string]func(context.Context) (int, error){
		"connected":         func(context.Context) (int, error) { return 1, nil },
		"probe unavailable": func(context.Context) (int, error) { return 0, errors.New("probe failed") },
	} {
		t.Run(name, func(t *testing.T) {
			beforeLists := fake.listCount.Load()
			manager.probeKeys = probe
			err := manager.Ensure(context.Background())
			if !errors.Is(err, primaryErr) || manager.CurrentSigner() != signing.SignerYubiKey {
				t.Fatalf("route error=%v signer=%q", err, manager.CurrentSigner())
			}
			if fake.listCount.Load() != beforeLists {
				t.Fatal("primary route contacted the fallback agent")
			}
		})
	}
}

func TestFallbackRejectsManagedSocketAlias(t *testing.T) {
	target := fallbackPublicKey(t)
	path := serveFallbackAgent(t, &fallbackTestAgent{keys: []*agent.Key{agentKey(target)}})
	cfg := fallbackConfig(target, path)
	cfg.SocketPath = path
	_, err := InspectFallback(context.Background(), cfg)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("managed socket")) {
		t.Fatalf("managed socket error = %v", err)
	}
}

func TestFallbackIdentityQueryHonorsCancellation(t *testing.T) {
	target := fallbackPublicKey(t)
	fake := &fallbackTestAgent{
		keys:        []*agent.Key{agentKey(target)},
		listStarted: make(chan struct{}),
		listRelease: make(chan struct{}),
	}
	t.Cleanup(func() { close(fake.listRelease) })
	cfg := fallbackConfig(target, serveFallbackAgent(t, fake))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := InspectFallback(ctx, cfg)
		result <- err
	}()
	select {
	case <-fake.listStarted:
	case <-time.After(time.Second):
		t.Fatal("fallback identity query did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, signing.ErrFallbackUnavailable) {
			t.Fatalf("canceled fallback error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback identity query ignored cancellation")
	}
}

func TestFallbackRoundTripReplaysSessionBind(t *testing.T) {
	target := fallbackPublicKey(t)
	fake := &fallbackTestAgent{keys: []*agent.Key{agentKey(target)}}
	fallbackSocket := serveFallbackAgent(t, fake)
	cfg := fallbackConfig(target, fallbackSocket)
	publicDir, err := os.MkdirTemp("/tmp", "yt-fallback-public-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(publicDir) })
	cfg.SocketPath = filepath.Join(publicDir, "agent.sock")
	listener, err := agentproxy.Listen(cfg.SocketPath)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox does not permit Unix socket creation")
		}
		t.Fatal(err)
	}
	defer listener.Close()

	manager := New(cfg, system.Dependencies{}, "/bin/false", filepath.Join(publicDir, "config.json"))
	manager.probeKeys = func(context.Context) (int, error) { return 0, nil }
	coordinator := signing.New(manager, nil, time.Second)
	server := &agentproxy.Server{
		TargetKey:      target,
		Comment:        "YubiTouch PIV 9A",
		BackendFactory: manager.Connect,
		Coordinator:    coordinator,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()

	conn, err := net.DialTimeout("unix", cfg.SocketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(conn)
	if _, err := client.Extension("session-bind@openssh.com", []byte("binding")); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := client.Sign(target, []byte("request")); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	_ = conn.Close()
	if fake.extensionCount.Load() != 1 || fake.signCount.Load() != 1 {
		t.Fatalf("fallback extensions=%d signs=%d", fake.extensionCount.Load(), fake.signCount.Load())
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback proxy did not stop")
	}
}

func fallbackPublicKey(t *testing.T) ssh.PublicKey {
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

func fallbackConfig(target ssh.PublicKey, socket string) config.Config {
	return config.Config{
		PublicKey:           target,
		FallbackAgent:       config.FallbackAgent1Password,
		FallbackAgentSocket: socket,
		SocketPath:          socket + ".public",
		BackendSocketPath:   socket + ".backend",
	}
}

func serveFallbackAgent(t *testing.T, fake agent.ExtendedAgent) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "yt-fallback-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
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
				_ = agent.ServeAgent(fake, conn)
			}()
		}
	}()
	return path
}

func systemDependenciesForFallback() system.Dependencies {
	return system.Dependencies{}
}
