package ageipc

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mofelee/yubitouch/internal/agentproxy"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/clientidentity"
	"github.com/mofelee/yubitouch/internal/signing"
)

const (
	defaultMaxConcurrent   = 4
	defaultReadTimeout     = 5 * time.Second
	defaultWriteTimeout    = 5 * time.Second
	defaultRequestTimeout  = 2 * time.Minute
	disconnectPollInterval = 25 * time.Millisecond
	trailingProbeTimeout   = time.Millisecond
)

// Handler performs one private-key request. The returned byte slice transfers
// ownership to the server and is cleared before the connection is closed.
// A successful call returns exactly 16 bytes and an empty class. Failures must
// return one of the predefined classes; arbitrary strings become internal.
type Handler interface {
	Unwrap(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass)
}

// HandlerFunc adapts a function into a Handler.
type HandlerFunc func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass)

func (f HandlerFunc) Unwrap(ctx context.Context, requester signing.Requester, request ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
	return f(ctx, requester, request)
}

// Server serves one framed request and one framed response per connection.
type Server struct {
	Handler        Handler
	MaxConcurrent  int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	RequestTimeout time.Duration

	// The following hooks are primarily for deterministic security tests.
	PeerUID           func(net.Conn) (uint32, error)
	CurrentUID        func() uint32
	RequesterResolver func(net.Conn) signing.Requester
	DisconnectWatcher func(context.Context, net.Conn)
}

// Listen creates a mode-0600 Unix socket in a private directory and safely
// replaces only an inactive socket at the requested path.
func Listen(path string) (net.Listener, error) {
	return agentproxy.Listen(path)
}

// Serve accepts bounded concurrent connections until ctx is canceled.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if listener == nil {
		return errors.New("age IPC listener is required")
	}
	if s.Handler == nil {
		return errors.New("age IPC handler is required")
	}
	limit := s.MaxConcurrent
	if limit == 0 {
		limit = defaultMaxConcurrent
	}
	if limit < 0 {
		return errors.New("age IPC concurrency limit is invalid")
	}
	semaphore := make(chan struct{}, limit)
	var connectionsMu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var connectionsWG sync.WaitGroup
	closeConnections := func() {
		connectionsMu.Lock()
		defer connectionsMu.Unlock()
		for conn := range connections {
			_ = conn.Close()
		}
	}
	shutdownDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			closeConnections()
		case <-shutdownDone:
		}
	}()
	defer close(shutdownDone)

	for {
		conn, err := listener.Accept()
		if err != nil {
			closeConnections()
			connectionsWG.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case semaphore <- struct{}{}:
			connectionsMu.Lock()
			connections[conn] = struct{}{}
			connectionsMu.Unlock()
			connectionsWG.Add(1)
			go func() {
				defer connectionsWG.Done()
				defer func() { <-semaphore }()
				defer func() {
					connectionsMu.Lock()
					delete(connections, conn)
					connectionsMu.Unlock()
				}()
				s.serveConn(ctx, conn)
			}()
		default:
			// Reject synchronously so an accept flood cannot create unbounded goroutines.
			s.rejectBusy(conn)
		}
	}
}

func (s *Server) rejectBusy(conn net.Conn) {
	defer conn.Close()
	if !s.authorized(conn) {
		s.writeFailure(conn, ClassUnauthorized)
		return
	}
	readTimeout := s.ReadTimeout
	if readTimeout <= 0 || readTimeout > 100*time.Millisecond {
		readTimeout = 100 * time.Millisecond
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return
	}
	payload, err := readFrame(conn)
	clear(payload)
	if err != nil {
		return
	}
	s.writeFailure(conn, ClassBusy)
}

func (s *Server) serveConn(parent context.Context, conn net.Conn) {
	defer conn.Close()
	if !s.authorized(conn) {
		s.writeFailure(conn, ClassUnauthorized)
		return
	}
	readTimeout := s.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return
	}
	payload, err := readFrame(conn)
	if err != nil {
		if isTimeout(err) {
			s.writeFailure(conn, ClassTimeout)
		} else {
			s.writeFailure(conn, ClassInvalidRequest)
		}
		return
	}
	defer clear(payload)
	request, err := unmarshalRequest(payload)
	if err != nil {
		s.writeFailure(conn, ClassInvalidRequest)
		return
	}
	if hasImmediateTrailingData(conn) {
		return
	}

	resolver := s.RequesterResolver
	if resolver == nil {
		resolver = clientidentity.Resolve
	}
	requester := resolver(conn)
	requestTimeout := s.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultRequestTimeout
	}
	requestCtx, cancelRequest := context.WithTimeout(parent, requestTimeout)
	defer cancelRequest()
	watchCtx, cancelWatch := context.WithCancel(parent)
	watchDone := make(chan struct{})
	var disconnected atomic.Bool
	watcher := s.DisconnectWatcher
	if watcher == nil {
		watcher = watchDisconnect
	}
	go func() {
		defer close(watchDone)
		watcher(watchCtx, conn)
		if watchCtx.Err() == nil {
			disconnected.Store(true)
			cancelRequest()
		}
	}()

	fileKey, class := s.callHandler(requestCtx, requester, request)
	defer clear(fileKey)
	cancelWatch()
	<-watchDone
	if disconnected.Load() || hasImmediateTrailingData(conn) {
		return
	}
	if err := requestCtx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			class = ClassTimeout
		} else {
			class = ClassCanceled
		}
		clear(fileKey)
		fileKey = nil
	}
	if class != "" {
		s.writeFailure(conn, class)
		return
	}
	if len(fileKey) != fileKeySize {
		s.writeFailure(conn, ClassInternal)
		return
	}
	payload, err = marshalSuccess(fileKey)
	if err != nil {
		s.writeFailure(conn, ClassInternal)
		return
	}
	defer clear(payload)
	s.writePayload(conn, payload)
}

func (s *Server) callHandler(ctx context.Context, requester signing.Requester, request ageprofile.UnwrapRequest) (fileKey []byte, class ErrorClass) {
	defer func() {
		if recover() != nil {
			clear(fileKey)
			fileKey = nil
			class = ClassInternal
		}
	}()
	fileKey, class = s.Handler.Unwrap(ctx, requester, request)
	if class != "" && !validErrorClass(class) {
		class = ClassInternal
	}
	return fileKey, class
}

func (s *Server) authorized(conn net.Conn) bool {
	peerUID := s.PeerUID
	if peerUID == nil {
		peerUID = platformPeerUID
	}
	uid, err := peerUID(conn)
	if err != nil {
		return false
	}
	currentUID := s.CurrentUID
	if currentUID == nil {
		currentUID = func() uint32 { return uint32(os.Geteuid()) }
	}
	return uid == currentUID()
}

func (s *Server) writeFailure(conn net.Conn, class ErrorClass) {
	payload := marshalFailure(class)
	defer clear(payload)
	s.writePayload(conn, payload)
}

func (s *Server) writePayload(conn net.Conn, payload []byte) {
	writeTimeout := s.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultWriteTimeout
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return
	}
	_ = writeFrame(conn, payload)
}

func hasImmediateTrailingData(conn net.Conn) bool {
	if err := conn.SetReadDeadline(time.Now().Add(trailingProbeTimeout)); err != nil {
		return true
	}
	var probe [1]byte
	n, err := conn.Read(probe[:])
	_ = conn.SetReadDeadline(time.Time{})
	if n > 0 {
		return true
	}
	if err == nil {
		return false
	}
	return !isTimeout(err)
}

func watchDisconnect(ctx context.Context, conn net.Conn) {
	var probe [1]byte
	for ctx.Err() == nil {
		if err := conn.SetReadDeadline(time.Now().Add(disconnectPollInterval)); err != nil {
			return
		}
		n, err := conn.Read(probe[:])
		if n > 0 {
			return
		}
		if err == nil {
			continue
		}
		if !isTimeout(err) {
			return
		}
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
