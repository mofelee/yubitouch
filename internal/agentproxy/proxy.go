package agentproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/mofelee/yubitouch/internal/signing"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrKeyNotAllowed   = errors.New("agent: key is not exposed by YubiTouch")
	ErrOperationDenied = errors.New("agent: operation is disabled by YubiTouch")
)

const sessionBindExtension = "session-bind@openssh.com"

const (
	maxPendingSessionBinds = 16
	maxPendingBytes        = 1 << 20
)

type Backend interface {
	agent.ExtendedAgent
	io.Closer
}

type BackendFactory func(context.Context) (Backend, error)

type Server struct {
	TargetKey      ssh.PublicKey
	Comment        string
	BackendFactory BackendFactory
	Coordinator    *signing.Coordinator
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
		connectionWG.Add(1)
		go func() {
			defer connectionWG.Done()
			defer func() {
				connectionMu.Lock()
				delete(connections, conn)
				connectionMu.Unlock()
			}()
			s.serveConn(ctx, conn)
		}()
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	frontend := &connectionAgent{
		ctx:            ctx,
		target:         s.TargetKey,
		comment:        s.Comment,
		backendFactory: s.BackendFactory,
		coordinator:    s.Coordinator,
	}
	defer frontend.close()
	_ = agent.ServeAgent(frontend, conn)
}

type connectionAgent struct {
	ctx            context.Context
	target         ssh.PublicKey
	comment        string
	backendFactory BackendFactory
	coordinator    *signing.Coordinator

	mu           sync.Mutex
	backend      Backend
	pending      []pendingExtension
	pendingBytes int
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
	backend, err := a.getBackend()
	if err != nil {
		return nil, err
	}
	return a.coordinator.Sign(a.ctx, func() (*ssh.Signature, error) {
		return backend.SignWithFlags(key, data, flags)
	})
}

func (a *connectionAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == sessionBindExtension {
		a.mu.Lock()
		if a.backend == nil {
			if len(a.pending) >= maxPendingSessionBinds || a.pendingBytes+len(contents) > maxPendingBytes {
				a.mu.Unlock()
				return nil, errors.New("agent: too many pending session-bind extensions")
			}
			a.pending = append(a.pending, pendingExtension{
				typeName: extensionType,
				contents: append([]byte(nil), contents...),
			})
			a.pendingBytes += len(contents)
			a.mu.Unlock()
			return []byte{6}, nil
		}
		backend := a.backend
		a.mu.Unlock()
		return backend.Extension(extensionType, contents)
	}
	backend, err := a.getBackend()
	if err != nil {
		return nil, err
	}
	return backend.Extension(extensionType, contents)
}

func (a *connectionAgent) Add(agent.AddedKey) error       { return ErrOperationDenied }
func (a *connectionAgent) Remove(ssh.PublicKey) error     { return ErrOperationDenied }
func (a *connectionAgent) RemoveAll() error               { return ErrOperationDenied }
func (a *connectionAgent) Lock([]byte) error              { return ErrOperationDenied }
func (a *connectionAgent) Unlock([]byte) error            { return ErrOperationDenied }
func (a *connectionAgent) Signers() ([]ssh.Signer, error) { return nil, ErrOperationDenied }

func (a *connectionAgent) getBackend() (Backend, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backend != nil {
		return a.backend, nil
	}
	backend, err := a.backendFactory(a.ctx)
	if err != nil {
		return nil, err
	}
	for _, extension := range a.pending {
		if _, err := backend.Extension(extension.typeName, extension.contents); err != nil {
			_ = backend.Close()
			return nil, err
		}
	}
	a.pending = nil
	a.pendingBytes = 0
	a.backend = backend
	return backend, nil
}

func (a *connectionAgent) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backend != nil {
		_ = a.backend.Close()
		a.backend = nil
	}
}

func sameKey(left ssh.PublicKey, right ssh.PublicKey) bool {
	if left == nil || right == nil {
		return false
	}
	return bytes.Equal(left.Marshal(), right.Marshal())
}
