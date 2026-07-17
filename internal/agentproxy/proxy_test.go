package agentproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/signing"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type fakeBackend struct {
	signCount   atomic.Int32
	closed      atomic.Bool
	extensions  atomic.Int32
	listFailure atomic.Bool
}

func (b *fakeBackend) List() ([]*agent.Key, error) {
	if b.listFailure.Load() {
		return nil, errors.New("backend connection is stale")
	}
	return nil, nil
}
func (b *fakeBackend) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return b.SignWithFlags(key, data, 0)
}
func (b *fakeBackend) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	b.signCount.Add(1)
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, ed25519.SignatureSize)}, nil
}
func (b *fakeBackend) Add(agent.AddedKey) error       { return nil }
func (b *fakeBackend) Remove(ssh.PublicKey) error     { return nil }
func (b *fakeBackend) RemoveAll() error               { return nil }
func (b *fakeBackend) Lock([]byte) error              { return nil }
func (b *fakeBackend) Unlock([]byte) error            { return nil }
func (b *fakeBackend) Signers() ([]ssh.Signer, error) { return nil, nil }
func (b *fakeBackend) Extension(string, []byte) ([]byte, error) {
	b.extensions.Add(1)
	return []byte{6}, nil
}
func (b *fakeBackend) Close() error {
	b.closed.Store(true)
	return nil
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

func TestListDoesNotCreateBackend(t *testing.T) {
	target := newPublicKey(t)
	var factories atomic.Int32
	a := &connectionAgent{
		ctx:     context.Background(),
		target:  target,
		comment: "YubiTouch PIV 9A",
		backendFactory: func(context.Context) (Backend, error) {
			factories.Add(1)
			return &fakeBackend{}, nil
		},
		coordinator: signing.New(nil, nil, time.Second),
	}
	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !stringEqual(keys[0].Blob, target.Marshal()) {
		t.Fatalf("unexpected keys: %+v", keys)
	}
	if factories.Load() != 0 {
		t.Fatal("List created a backend connection")
	}
}

func TestRejectsOtherKeyAndMutations(t *testing.T) {
	target := newPublicKey(t)
	other := newPublicKey(t)
	a := &connectionAgent{
		ctx:            context.Background(),
		target:         target,
		backendFactory: func(context.Context) (Backend, error) { return &fakeBackend{}, nil },
		coordinator:    signing.New(nil, nil, time.Second),
	}
	if _, err := a.Sign(other, []byte("request")); !errors.Is(err, ErrKeyNotAllowed) {
		t.Fatalf("Sign error = %v", err)
	}
	if err := a.Add(agent.AddedKey{}); !errors.Is(err, ErrOperationDenied) {
		t.Fatalf("Add error = %v", err)
	}
	if err := a.Remove(target); !errors.Is(err, ErrOperationDenied) {
		t.Fatalf("Remove error = %v", err)
	}
	if err := a.Lock(nil); !errors.Is(err, ErrOperationDenied) {
		t.Fatalf("Lock error = %v", err)
	}
}

func TestSessionBindIsReplayedWithoutEagerBackend(t *testing.T) {
	target := newPublicKey(t)
	backend := &fakeBackend{}
	var factories atomic.Int32
	a := &connectionAgent{
		ctx:    context.Background(),
		target: target,
		backendFactory: func(context.Context) (Backend, error) {
			factories.Add(1)
			return backend, nil
		},
		coordinator: signing.New(nil, nil, time.Second),
	}
	response, err := a.Extension(sessionBindExtension, []byte("binding"))
	if err != nil || len(response) != 1 || response[0] != 6 {
		t.Fatalf("extension response = %v, %v", response, err)
	}
	if factories.Load() != 0 {
		t.Fatal("session-bind created a backend before signing")
	}
	if _, err := a.Sign(target, []byte("request")); err != nil {
		t.Fatal(err)
	}
	if factories.Load() != 1 || backend.extensions.Load() != 1 {
		t.Fatalf("factory=%d extension=%d", factories.Load(), backend.extensions.Load())
	}
}

func TestStaleBackendReconnectsAndReplaysSessionBind(t *testing.T) {
	target := newPublicKey(t)
	first := &fakeBackend{}
	second := &fakeBackend{}
	backends := []*fakeBackend{first, second}
	var factories atomic.Int32
	a := &connectionAgent{
		ctx:    context.Background(),
		target: target,
		backendFactory: func(context.Context) (Backend, error) {
			index := int(factories.Add(1)) - 1
			return backends[index], nil
		},
		coordinator: signing.New(nil, nil, time.Second),
	}
	if _, err := a.Sign(target, []byte("first request")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Extension(sessionBindExtension, []byte("binding")); err != nil {
		t.Fatal(err)
	}
	first.listFailure.Store(true)
	if _, err := a.Sign(target, []byte("second request")); err != nil {
		t.Fatal(err)
	}
	if factories.Load() != 2 || !first.closed.Load() || second.extensions.Load() != 1 || second.signCount.Load() != 1 {
		t.Fatalf("factories=%d first_closed=%v second_extensions=%d second_signs=%d",
			factories.Load(), first.closed.Load(), second.extensions.Load(), second.signCount.Load())
	}
}

func TestSessionBindRetentionIsBounded(t *testing.T) {
	a := &connectionAgent{
		ctx:            context.Background(),
		target:         newPublicKey(t),
		backendFactory: func(context.Context) (Backend, error) { return &fakeBackend{}, nil },
		coordinator:    signing.New(nil, nil, time.Second),
	}
	for range maxPendingSessionBinds {
		if _, err := a.Extension(sessionBindExtension, []byte("binding")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Extension(sessionBindExtension, []byte("one too many")); err == nil {
		t.Fatal("session-bind retention accepted too many entries")
	}
}

func TestServeAgentCreatesBackendPerClient(t *testing.T) {
	target := newPublicKey(t)
	var mu sync.Mutex
	var backends []*fakeBackend
	server := &Server{
		TargetKey: target,
		Comment:   "YubiTouch PIV 9A",
		BackendFactory: func(context.Context) (Backend, error) {
			backend := &fakeBackend{}
			mu.Lock()
			backends = append(backends, backend)
			mu.Unlock()
			return backend, nil
		},
		Coordinator: signing.New(nil, nil, time.Second),
	}

	for range 2 {
		serverConn, clientConn := net.Pipe()
		go server.serveConn(context.Background(), serverConn)
		client := agent.NewClient(clientConn)
		keys, err := client.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 1 {
			t.Fatalf("List returned %d keys", len(keys))
		}
		if _, err := client.Sign(target, []byte("request")); err != nil {
			t.Fatal(err)
		}
		_ = clientConn.Close()
	}

	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		count := len(backends)
		allClosed := count == 2 && backends[0].closed.Load() && backends[1].closed.Load()
		mu.Unlock()
		if allClosed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backend state did not settle: count=%d", count)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestListenSecuresAndRemovesSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "runtime", "agent.sock")
	listener, err := Listen(path)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("sandbox does not permit Unix socket creation")
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists: %v", err)
	}
}

func stringEqual(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
