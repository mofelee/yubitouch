package agentproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
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

type blockingBackend struct {
	fakeBackend
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type cancelableBackend struct {
	fakeBackend
	started   chan struct{}
	stopped   chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

type writeSignalConn struct {
	net.Conn
	wrote chan struct{}
	once  sync.Once
}

type orderedInitializer struct {
	ready atomic.Bool
}

func (i *orderedInitializer) Ensure(context.Context) error {
	i.ready.Store(true)
	return nil
}

func (c *writeSignalConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.once.Do(func() { close(c.wrote) })
	}
	return n, err
}

func (b *cancelableBackend) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	b.signCount.Add(1)
	b.startOnce.Do(func() { close(b.started) })
	<-b.stopped
	return nil, errors.New("backend connection closed")
}

func (b *cancelableBackend) Close() error {
	b.fakeBackend.Close()
	b.stopOnce.Do(func() { close(b.stopped) })
	return nil
}

func (b *blockingBackend) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	b.signCount.Add(1)
	b.once.Do(func() { close(b.started) })
	<-b.release
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, ed25519.SignatureSize)}, nil
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

func TestBackendIsCreatedAfterSigningInitialization(t *testing.T) {
	initializer := &orderedInitializer{}
	target := newPublicKey(t)
	a := &connectionAgent{
		ctx:    context.Background(),
		target: target,
		backendFactory: func(context.Context) (Backend, error) {
			if !initializer.ready.Load() {
				t.Fatal("backend was created before signing initialization")
			}
			return &fakeBackend{}, nil
		},
		coordinator: signing.New(initializer, nil, time.Second),
	}
	if _, err := a.Sign(target, []byte("request")); err != nil {
		t.Fatal(err)
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

func TestUnknownExtensionDoesNotCreateBackend(t *testing.T) {
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
	if _, err := a.Extension("query@example.com", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("extension before sign error = %v", err)
	}
	if factories.Load() != 0 {
		t.Fatal("extension created backend before signing")
	}
	if _, err := a.Sign(target, []byte("request")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Extension("query@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if factories.Load() != 1 || backend.extensions.Load() != 1 {
		t.Fatalf("factories=%d extensions=%d", factories.Load(), backend.extensions.Load())
	}
}

func TestOversizedAgentFrameIsRejectedBeforeBackendCreation(t *testing.T) {
	target := newPublicKey(t)
	var factories atomic.Int32
	server := &Server{
		TargetKey: target,
		BackendFactory: func(context.Context) (Backend, error) {
			factories.Add(1)
			return &fakeBackend{}, nil
		},
		Coordinator: signing.New(nil, nil, time.Second),
	}
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConn(context.Background(), serverConn)
		close(done)
	}()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxAgentRequestBytes+1)
	if _, err := clientConn.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	var response [1]byte
	if _, err := clientConn.Read(response[:]); err == nil {
		t.Fatal("oversized request did not close the connection")
	}
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("agent server did not reject oversized request")
	}
	if factories.Load() != 0 {
		t.Fatal("oversized request created a backend")
	}
}

func TestBoundedAgentConnAcceptsCompleteFrames(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	bounded := &boundedAgentConn{Conn: serverConn}
	payloads := [][]byte{{11}, {27, 0, 0, 0, 0}}
	go func() {
		for _, payload := range payloads {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
			_, _ = clientConn.Write(append(header[:], payload...))
		}
	}()
	for _, want := range payloads {
		var header [4]byte
		if _, err := io.ReadFull(bounded, header[:]); err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint32(header[:]); got != uint32(len(want)) {
			t.Fatalf("frame length = %d, want %d", got, len(want))
		}
		payload := make([]byte, len(want))
		if _, err := io.ReadFull(bounded, payload); err != nil {
			t.Fatal(err)
		}
		if !stringEqual(payload, want) {
			t.Fatalf("payload = %v, want %v", payload, want)
		}
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

func TestClientDisconnectCancelsQueuedSign(t *testing.T) {
	target := newPublicKey(t)
	first := &blockingBackend{started: make(chan struct{}), release: make(chan struct{})}
	second := &fakeBackend{}
	var factories atomic.Int32
	secondServerConn, secondClientConn := net.Pipe()
	defer secondClientConn.Close()
	disconnectSecond := make(chan struct{})
	server := &Server{
		TargetKey: target,
		BackendFactory: func(context.Context) (Backend, error) {
			if factories.Add(1) == 1 {
				return first, nil
			}
			return second, nil
		},
		Coordinator: signing.New(nil, nil, time.Second),
		disconnectWatcher: func(ctx context.Context, conn net.Conn) {
			if conn == secondServerConn {
				select {
				case <-disconnectSecond:
				case <-ctx.Done():
				}
				return
			}
			<-ctx.Done()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstServerConn, firstClientConn := net.Pipe()
	defer firstClientConn.Close()
	go server.serveConn(ctx, firstServerConn)
	firstResult := make(chan error, 1)
	go func() {
		_, err := agent.NewClient(firstClientConn).Sign(target, []byte("first request"))
		firstResult <- err
	}()
	select {
	case <-first.started:
	case <-time.After(time.Second):
		t.Fatal("first signature did not start")
	}

	go server.serveConn(ctx, secondServerConn)
	secondResult := make(chan error, 1)
	secondRequestWritten := make(chan struct{})
	secondClient := &writeSignalConn{Conn: secondClientConn, wrote: secondRequestWritten}
	go func() {
		_, err := agent.NewClient(secondClient).Sign(target, []byte("second request"))
		secondResult <- err
	}()
	select {
	case <-secondRequestWritten:
	case <-time.After(time.Second):
		t.Fatal("second request was not written to the agent connection")
	}
	if factories.Load() != 1 {
		t.Fatalf("queued request created %d backends, want only the active backend", factories.Load())
	}
	_ = secondClientConn.Close()
	close(disconnectSecond)
	select {
	case err := <-secondResult:
		if err == nil {
			t.Fatal("disconnected client unexpectedly received a signature")
		}
	case <-time.After(time.Second):
		t.Fatal("disconnected client did not return")
	}
	if second.closed.Load() || second.signCount.Load() != 0 || factories.Load() != 1 {
		t.Fatalf("queued request backend state: factories=%d closed=%v signs=%d",
			factories.Load(), second.closed.Load(), second.signCount.Load())
	}

	close(first.release)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first signature did not finish")
	}
}

func TestWatchDisconnectDetectsUnixPeerClose(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-disconnect-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, err := net.Listen("unix", filepath.Join(dir, "watch.sock"))
	if errors.Is(err, syscall.EPERM) {
		t.Skip("sandbox does not permit Unix socket creation")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverConn := <-accepted
	if serverConn == nil {
		t.Fatal("listener did not accept the client")
	}
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		watchDisconnect(ctx, serverConn)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("disconnect watcher returned while the peer was connected")
	case <-time.After(25 * time.Millisecond):
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disconnect watcher did not detect peer close")
	}
}

func TestActiveDisconnectClosesBackendConnection(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-active-disconnect-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, err := Listen(filepath.Join(dir, "runtime", "agent.sock"))
	if errors.Is(err, syscall.EPERM) {
		t.Skip("sandbox does not permit Unix socket creation")
	}
	if err != nil {
		t.Fatal(err)
	}
	target := newPublicKey(t)
	backend := &cancelableBackend{started: make(chan struct{}), stopped: make(chan struct{})}
	server := &Server{
		TargetKey:      target,
		BackendFactory: func(context.Context) (Backend, error) { return backend, nil },
		Coordinator:    signing.New(nil, nil, time.Second),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = listener.Close() })
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(ctx, listener) }()
	clientConn, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		cancel()
		<-serverResult
		t.Fatal(err)
	}
	signResult := make(chan error, 1)
	go func() {
		_, err := agent.NewClient(clientConn).Sign(target, []byte("request"))
		signResult <- err
	}()
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("signature did not start")
	}
	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-signResult:
		if err == nil {
			t.Fatal("disconnected client unexpectedly received a signature")
		}
	case <-time.After(time.Second):
		t.Fatal("client sign did not return after disconnect")
	}
	select {
	case <-backend.stopped:
	case <-time.After(time.Second):
		t.Fatal("backend connection was not closed after client disconnect")
	}
	if !backend.closed.Load() {
		t.Fatal("backend did not record Close")
	}
	cancel()
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("agent server did not stop")
	}
}

func TestUserCancellationClosesBackendAndNextRequestReconnects(t *testing.T) {
	target := newPublicKey(t)
	first := &cancelableBackend{started: make(chan struct{}), stopped: make(chan struct{})}
	second := &fakeBackend{}
	var factories atomic.Int32
	coordinator := signing.New(nil, nil, time.Second)
	a := &connectionAgent{
		ctx:     context.Background(),
		target:  target,
		comment: "YubiTouch PIV 9A",
		backendFactory: func(context.Context) (Backend, error) {
			if factories.Add(1) == 1 {
				return first, nil
			}
			return second, nil
		},
		coordinator: coordinator,
	}
	defer a.close()

	firstResult := make(chan error, 1)
	go func() {
		_, err := a.Sign(target, []byte("first request"))
		firstResult <- err
	}()
	select {
	case <-first.started:
	case <-time.After(time.Second):
		t.Fatal("first signature did not start")
	}
	if !coordinator.CancelCurrent() {
		t.Fatal("active signature was not canceled")
	}
	if err := <-firstResult; !errors.Is(err, signing.ErrCanceled) {
		t.Fatalf("first error = %v, want canceled", err)
	}
	if !first.closed.Load() {
		t.Fatal("canceled backend connection was not closed")
	}

	if _, err := a.Sign(target, []byte("second request")); err != nil {
		t.Fatalf("next signature failed: %v", err)
	}
	if factories.Load() != 2 || second.signCount.Load() != 1 {
		t.Fatalf("factories=%d second_signs=%d", factories.Load(), second.signCount.Load())
	}
}

type requesterRecorder struct {
	events chan signing.Event
}

func (r requesterRecorder) Handle(event signing.Event) {
	r.events <- event
}

func TestConnectionAgentPublishesCapturedRequester(t *testing.T) {
	target := newPublicKey(t)
	events := make(chan signing.Event, 3)
	requester := signing.Requester{Name: "DebianForm", DirectClient: "ssh"}
	a := &connectionAgent{
		ctx:       context.Background(),
		target:    target,
		comment:   "YubiTouch PIV 9A",
		requester: requester,
		backendFactory: func(context.Context) (Backend, error) {
			return &fakeBackend{}, nil
		},
		coordinator: signing.New(nil, requesterRecorder{events: events}, time.Second),
	}
	defer a.close()
	if _, err := a.Sign(target, []byte("request")); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		event := <-events
		if event.Requester != requester {
			t.Fatalf("event requester = %+v, want %+v", event.Requester, requester)
		}
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
