package agentproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/mofelee/yubitouch/internal/clientidentity"
	"github.com/mofelee/yubitouch/internal/signing"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

var (
	ErrKeyNotAllowed   = errors.New("agent: key is not exposed by YubiTouch")
	ErrOperationDenied = errors.New("agent: operation is disabled by YubiTouch")
	errRequestTooLarge = errors.New("agent: request exceeds YubiTouch size limit")
)

const sessionBindExtension = "session-bind@openssh.com"

const (
	maxPendingSessionBinds = 16
	maxPendingBytes        = 1 << 20
	maxAgentRequestBytes   = 1 << 20
)

type Backend interface {
	agent.ExtendedAgent
	io.Closer
}

type closeAfterSigner interface {
	CloseAfterSign() bool
}

type BackendFactory func(context.Context) (Backend, error)

type Server struct {
	TargetKey         ssh.PublicKey
	Comment           string
	BackendFactory    BackendFactory
	Coordinator       *signing.Coordinator
	disconnectWatcher func(context.Context, net.Conn)
	requesterResolver func(net.Conn) signing.Requester
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s.TargetKey == nil {
		return errors.New("agent proxy: target key is required")
	}
	if s.BackendFactory == nil {
		return errors.New("agent proxy: backend factory is required")
	}
	if s.Coordinator == nil {
		return errors.New("agent proxy: signing coordinator is required")
	}

	var connectionMu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var connectionWG sync.WaitGroup
	closeConnections := func() {
		connectionMu.Lock()
		defer connectionMu.Unlock()
		for conn := range connections {
			_ = conn.Close()
		}
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		closeConnections()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				connectionWG.Wait()
				return nil
			}
			closeConnections()
			connectionWG.Wait()
			return err
		}
		connectionMu.Lock()
		connections[conn] = struct{}{}
		connectionMu.Unlock()
		resolver := s.requesterResolver
		if resolver == nil {
			resolver = clientidentity.Resolve
		}
		requester := resolver(conn)
		connectionWG.Add(1)
		go func() {
			defer connectionWG.Done()
			defer func() {
				connectionMu.Lock()
				delete(connections, conn)
				connectionMu.Unlock()
			}()
			s.serveConnFor(ctx, conn, requester)
		}()
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	s.serveConnFor(ctx, conn, signing.Requester{})
}

func (s *Server) serveConnFor(ctx context.Context, conn net.Conn, requester signing.Requester) {
	connectionCtx, cancel := context.WithCancel(ctx)
	watcher := s.disconnectWatcher
	if watcher == nil {
		watcher = watchDisconnect
	}
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		watcher(connectionCtx, conn)
		cancel()
	}()
	defer func() {
		cancel()
		_ = conn.Close()
		<-watcherDone
	}()
	frontend := &connectionAgent{
		ctx:            connectionCtx,
		target:         s.TargetKey,
		comment:        s.Comment,
		backendFactory: s.BackendFactory,
		coordinator:    s.Coordinator,
		requester:      requester,
	}
	defer frontend.close()
	_ = agent.ServeAgent(frontend, &boundedAgentConn{Conn: conn})
}

type boundedAgentConn struct {
	net.Conn
	remaining uint32
}

func (c *boundedAgentConn) Read(p []byte) (int, error) {
	if c.remaining == 0 {
		if len(p) < 4 {
			return 0, io.ErrShortBuffer
		}
		var header [4]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length > maxAgentRequestBytes {
			return 0, errRequestTooLarge
		}
		copy(p, header[:])
		c.remaining = length
		return len(header), nil
	}
	if uint32(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= uint32(n)
	return n, err
}

func watchDisconnect(ctx context.Context, conn net.Conn) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		<-ctx.Done()
		return
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		<-ctx.Done()
		return
	}
	for ctx.Err() == nil {
		disconnected := false
		readable := false
		err := raw.Control(func(fd uintptr) {
			pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, pollErr := unix.Poll(pollFDs, 100)
			if pollErr != nil {
				if pollErr != unix.EINTR {
					disconnected = true
				}
				return
			}
			events := pollFDs[0].Revents
			if events&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				disconnected = true
				return
			}
			if events&unix.POLLIN == 0 {
				return
			}
			readable = true
			var buffer [1]byte
			n, _, recvErr := unix.Recvfrom(int(fd), buffer[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
			if n == 0 && recvErr == nil {
				disconnected = true
				return
			}
			if recvErr != nil && recvErr != unix.EAGAIN && recvErr != unix.EWOULDBLOCK && recvErr != unix.EINTR {
				disconnected = true
			}
		})
		if err != nil || disconnected {
			return
		}
		if readable {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
		}
	}
}

type connectionAgent struct {
	ctx            context.Context
	target         ssh.PublicKey
	comment        string
	backendFactory BackendFactory
	coordinator    *signing.Coordinator
	requester      signing.Requester

	mu           sync.Mutex
	backend      Backend
	bindings     []pendingExtension
	bindingBytes int
}

type pendingExtension struct {
	typeName string
	contents []byte
}

func (a *connectionAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{
		Format:  a.target.Type(),
		Blob:    append([]byte(nil), a.target.Marshal()...),
		Comment: a.comment,
	}}, nil
}

func (a *connectionAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *connectionAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !sameKey(a.target, key) {
		return nil, ErrKeyNotAllowed
	}
	return a.coordinator.SignContextCancelableFor(
		a.ctx,
		a.requester,
		func(requestCtx context.Context) (*ssh.Signature, error) {
			backend, err := a.getSigningBackend(requestCtx)
			if err != nil {
				return nil, err
			}
			if policy, ok := backend.(closeAfterSigner); ok && policy.CloseAfterSign() {
				defer a.closeSigningBackend()
			}
			return backend.SignWithFlags(key, data, flags)
		},
		a.closeSigningBackend,
	)
}

func (a *connectionAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == sessionBindExtension {
		a.mu.Lock()
		defer a.mu.Unlock()
		if len(a.bindings) >= maxPendingSessionBinds || a.bindingBytes+len(contents) > maxPendingBytes {
			return nil, errors.New("agent: too many pending session-bind extensions")
		}
		binding := pendingExtension{
			typeName: extensionType,
			contents: append([]byte(nil), contents...),
		}
		a.bindings = append(a.bindings, binding)
		a.bindingBytes += len(binding.contents)
		if a.backend == nil {
			return []byte{6}, nil
		}
		response, err := a.backend.Extension(extensionType, contents)
		if err != nil {
			last := len(a.bindings) - 1
			a.bindingBytes -= len(a.bindings[last].contents)
			zero(a.bindings[last].contents)
			a.bindings = a.bindings[:last]
		}
		return response, err
	}
	a.mu.Lock()
	backend := a.backend
	a.mu.Unlock()
	if backend == nil {
		return nil, agent.ErrExtensionUnsupported
	}
	return backend.Extension(extensionType, contents)
}

func (a *connectionAgent) Add(agent.AddedKey) error       { return ErrOperationDenied }
func (a *connectionAgent) Remove(ssh.PublicKey) error     { return ErrOperationDenied }
func (a *connectionAgent) RemoveAll() error               { return ErrOperationDenied }
func (a *connectionAgent) Lock([]byte) error              { return ErrOperationDenied }
func (a *connectionAgent) Unlock([]byte) error            { return ErrOperationDenied }
func (a *connectionAgent) Signers() ([]ssh.Signer, error) { return nil, ErrOperationDenied }

func (a *connectionAgent) getSigningBackend(ctx context.Context) (Backend, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backend != nil {
		if _, err := a.backend.List(); err == nil {
			return a.backend, nil
		}
		_ = a.backend.Close()
		a.backend = nil
	}
	return a.connectBackendLocked(ctx)
}

func (a *connectionAgent) connectBackendLocked(ctx context.Context) (Backend, error) {
	backend, err := a.backendFactory(ctx)
	if err != nil {
		return nil, err
	}
	for _, extension := range a.bindings {
		if _, err := backend.Extension(extension.typeName, extension.contents); err != nil {
			_ = backend.Close()
			return nil, err
		}
	}
	a.backend = backend
	return backend, nil
}

func (a *connectionAgent) closeSigningBackend() {
	a.mu.Lock()
	backend := a.backend
	a.backend = nil
	a.mu.Unlock()
	if backend != nil {
		_ = backend.Close()
	}
}

func (a *connectionAgent) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backend != nil {
		_ = a.backend.Close()
		a.backend = nil
	}
	for _, binding := range a.bindings {
		zero(binding.contents)
	}
	a.bindings = nil
	a.bindingBytes = 0
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func sameKey(left ssh.PublicKey, right ssh.PublicKey) bool {
	if left == nil || right == nil {
		return false
	}
	return bytes.Equal(left.Marshal(), right.Marshal())
}
