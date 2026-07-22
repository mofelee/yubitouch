package ageipc

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/signing"
)

func TestClientServerRoundTrip(t *testing.T) {
	request := testRequest(t, true)
	want := []byte("0123456789abcdef")
	server := testServer(HandlerFunc(func(_ context.Context, _ signing.Requester, got ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		if !reflect.DeepEqual(got, request) {
			t.Fatalf("request changed across IPC")
		}
		return append([]byte(nil), want...), ""
	}))
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConn(context.Background(), serverConn)
		close(done)
	}()
	client := NewClient("test.sock", time.Second)
	client.DialContext = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	got, err := client.Unwrap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if string(got) != string(want) {
		t.Fatalf("file key = %x, want %x", got, want)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server connection did not close")
	}
}

func TestStrictRequestValidation(t *testing.T) {
	request := testRequest(t, true)
	valid, err := marshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := requestToWire(request)
	if err != nil {
		t.Fatal(err)
	}

	marshalWire := func(edit func(*wireRequest)) []byte {
		copy := wire
		copy.Stanzas = append([]wireEnvelope(nil), wire.Stanzas...)
		edit(&copy)
		payload, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	tests := map[string][]byte{
		"malformed":          []byte(`{"version":`),
		"trailing value":     append(append([]byte(nil), valid...), []byte(` {}`)...),
		"unknown field":      append(valid[:len(valid)-1], []byte(`,"private_key":"must-not-pass"}`)...),
		"duplicate field":    []byte(strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1)),
		"invalid utf8":       append([]byte(`{"x":"`), 0xff, '"', '}'),
		"three stanzas":      marshalWire(func(value *wireRequest) { value.Stanzas = append(value.Stanzas, value.Stanzas[1]) }),
		"profile mismatch":   marshalWire(func(value *wireRequest) { value.ProfileID = strings.Repeat("f", 32) }),
		"key mismatch":       marshalWire(func(value *wireRequest) { value.HardwareKeyID = strings.Repeat("e", 32) }),
		"bad operation":      marshalWire(func(value *wireRequest) { value.Operation = "inspect" }),
		"long envelope path": marshalWire(func(value *wireRequest) { value.Stanzas[0].Path = strings.Repeat("x", 9) }),
		"noncanonical base64": marshalWire(func(value *wireRequest) {
			value.Stanzas[0].EphemeralPublicKey = strings.Repeat("A", 42) + "="
		}),
		"duplicate hardware": marshalWire(func(value *wireRequest) { value.Stanzas[1] = value.Stanzas[0] }),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := testServer(HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
				calls.Add(1)
				return []byte("0123456789abcdef"), ""
			}))
			response, ok := rawExchange(t, server, payload)
			if !ok {
				t.Fatal("server returned no failure response")
			}
			assertFailureClass(t, response, ClassInvalidRequest)
			if calls.Load() != 0 {
				t.Fatalf("handler calls = %d, want 0", calls.Load())
			}
		})
	}
}

func TestOversizedFrameRejectedBeforeAllocation(t *testing.T) {
	var calls atomic.Int32
	server := testServer(HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		calls.Add(1)
		return nil, ClassInternal
	}))
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConn(context.Background(), serverConn)
		close(done)
	}()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxFrameSize+1)
	if _, err := clientConn.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	response, err := readFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	assertFailureClass(t, response, ClassInvalidRequest)
	_ = clientConn.Close()
	<-done
	if calls.Load() != 0 {
		t.Fatal("oversized frame reached handler")
	}
}

func TestSecondFrameIsRejected(t *testing.T) {
	request := testRequest(t, false)
	payload, err := marshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := testServer(HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		calls.Add(1)
		return []byte("0123456789abcdef"), ""
	}))
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConn(context.Background(), serverConn)
		close(done)
	}()
	writeDone := make(chan error, 1)
	go func() {
		var frame []byte
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
		frame = append(frame, header[:]...)
		frame = append(frame, payload...)
		frame = append(frame, header[:]...)
		frame = append(frame, payload...)
		_, err := clientConn.Write(frame)
		writeDone <- err
	}()
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := readFrame(clientConn); err == nil {
		t.Fatal("connection with a second frame received a response")
	}
	_ = clientConn.Close()
	<-done
	<-writeDone
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}
}

func TestWrongPeerUIDRejected(t *testing.T) {
	request := testRequest(t, false)
	payload, err := marshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := testServer(HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		calls.Add(1)
		return nil, ClassInternal
	}))
	server.PeerUID = func(net.Conn) (uint32, error) { return 8, nil }
	response, ok := rawExchange(t, server, payload)
	if !ok {
		t.Fatal("server returned no unauthorized response")
	}
	assertFailureClass(t, response, ClassUnauthorized)
	if calls.Load() != 0 {
		t.Fatal("wrong-UID request reached handler")
	}
}

func TestServerBoundsConcurrentRequests(t *testing.T) {
	request := testRequest(t, false)
	started := make(chan struct{})
	release := make(chan struct{})
	server := testServer(HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		return []byte("0123456789abcdef"), ""
	}))
	server.MaxConcurrent = 1
	listener := newQueueListener()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()

	dial := func(context.Context, string, string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		if err := listener.deliver(serverConn); err != nil {
			_ = serverConn.Close()
			_ = clientConn.Close()
			return nil, err
		}
		return clientConn, nil
	}
	first := NewClient("test.sock", time.Second)
	first.DialContext = dial
	firstDone := make(chan error, 1)
	go func() {
		key, err := first.Unwrap(context.Background(), request)
		clear(key)
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first handler did not start")
	}
	second := NewClient("test.sock", time.Second)
	second.DialContext = dial
	key, err := second.Unwrap(context.Background(), request)
	clear(key)
	assertErrorClass(t, err, ClassBusy)
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-serveDone; err != nil {
		t.Fatal(err)
	}
}

func TestDisconnectCancelsHandler(t *testing.T) {
	request := testRequest(t, false)
	payload, err := marshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	canceled := make(chan struct{})
	server := testServer(HandlerFunc(func(ctx context.Context, _ signing.Requester, _ ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ClassCanceled
	}))
	server.DisconnectWatcher = nil
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConn(context.Background(), serverConn)
		close(done)
	}()
	if err := writeFrame(clientConn, payload); err != nil {
		t.Fatal(err)
	}
	<-started
	_ = clientConn.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel handler")
	}
	<-done
}

func TestRequestDeadlineReturnsOnlyTimeoutClass(t *testing.T) {
	request := testRequest(t, false)
	server := testServer(HandlerFunc(func(ctx context.Context, _ signing.Requester, _ ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		<-ctx.Done()
		return nil, ErrorClass("sensitive raw backend error")
	}))
	server.RequestTimeout = 20 * time.Millisecond
	serverConn, clientConn := net.Pipe()
	go server.serveConn(context.Background(), serverConn)
	client := NewClient("test.sock", time.Second)
	client.DialContext = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	key, err := client.Unwrap(context.Background(), request)
	clear(key)
	assertErrorClass(t, err, ClassTimeout)
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatal("error exposed handler detail")
	}
}

func TestHandlerFailureAndPanicAreRedacted(t *testing.T) {
	request := testRequest(t, false)
	payload, err := marshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Handler{
		"unknown class": HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
			return nil, ErrorClass("pin=very-secret")
		}),
		"panic": HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
			panic("private-reference=very-secret")
		}),
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			response, ok := rawExchange(t, testServer(handler), payload)
			if !ok {
				t.Fatal("server returned no redacted response")
			}
			if strings.Contains(string(response), "very-secret") {
				t.Fatal("response exposed handler detail")
			}
			assertFailureClass(t, response, ClassInternal)
		})
	}
}

func TestRequesterIsResolvedBeforeHandler(t *testing.T) {
	request := testRequest(t, false)
	want := signing.Requester{Name: "Test App", DirectClient: "age", BundleIdentifier: "com.example.test", VerifiedBundle: true}
	got := make(chan signing.Requester, 1)
	server := testServer(HandlerFunc(func(_ context.Context, requester signing.Requester, _ ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		got <- requester
		return []byte("0123456789abcdef"), ""
	}))
	server.RequesterResolver = func(net.Conn) signing.Requester { return want }
	payload, err := marshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := rawExchange(t, server, payload)
	if !ok {
		t.Fatal("server returned no response")
	}
	key, err := unmarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if requester := <-got; requester != want {
		t.Fatalf("requester = %#v, want %#v", requester, want)
	}
}

func TestClientRejectsMalformedAndSecretBearingResponse(t *testing.T) {
	request := testRequest(t, false)
	serverConn, clientConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		payload, err := readFrame(serverConn)
		clear(payload)
		if err != nil {
			return
		}
		_ = writeFrame(serverConn, []byte(`{"version":1,"status":"error","error":"pin=very-secret"}`))
	}()
	client := NewClient("test.sock", time.Second)
	client.DialContext = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	key, err := client.Unwrap(context.Background(), request)
	clear(key)
	assertErrorClass(t, err, ClassProtocolFailure)
	if strings.Contains(err.Error(), "very-secret") {
		t.Fatal("client error exposed response detail")
	}
}

func TestClientClassifiesCancellationAndUnavailableDaemon(t *testing.T) {
	request := testRequest(t, false)
	client := NewClient("missing.sock", time.Second)
	client.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("socket path and secret detail")
	}
	key, err := client.Unwrap(context.Background(), request)
	clear(key)
	assertErrorClass(t, err, ClassDaemonUnavailable)
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("client exposed dial error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key, err = client.Unwrap(ctx, request)
	clear(key)
	assertErrorClass(t, err, ClassCanceled)
}

func TestClientCancellationClosesEstablishedConnection(t *testing.T) {
	request := testRequest(t, false)
	serverConn, clientConn := net.Pipe()
	serverRead := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		payload, err := readFrame(serverConn)
		clear(payload)
		if err != nil {
			serverDone <- err
			return
		}
		close(serverRead)
		var one [1]byte
		_, err = serverConn.Read(one[:])
		serverDone <- err
	}()
	client := NewClient("test.sock", time.Minute)
	client.DialContext = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		key, err := client.Unwrap(ctx, request)
		clear(key)
		result <- err
	}()
	select {
	case <-serverRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive the request")
	}
	cancel()
	select {
	case err := <-result:
		assertErrorClass(t, err, ClassCanceled)
	case <-time.After(time.Second):
		t.Fatal("canceled client remained blocked on the socket")
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("server did not observe the client disconnect")
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe the canceled client disconnect")
	}
}

func TestClientCancellationAtCompleteResponseClearsFileKey(t *testing.T) {
	request := testRequest(t, false)
	want := []byte("0123456789abcdef")
	response, err := marshalSuccess(want)
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, response); err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		payload, err := readFrame(serverConn)
		clear(payload)
		if err == nil {
			_, _ = serverConn.Write(frame.Bytes())
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	wrapped := &cancelAfterReadConn{Conn: clientConn, remaining: frame.Len(), cancel: cancel}
	client := NewClient("test.sock", time.Second)
	client.DialContext = func(context.Context, string, string) (net.Conn, error) { return wrapped, nil }
	key, err := client.Unwrap(ctx, request)
	if key != nil {
		clear(key)
		t.Fatal("canceled response returned file key material")
	}
	assertErrorClass(t, err, ClassCanceled)
}

func TestListenCreatesPrivateRemovingSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "private", "age.sock")
	listener, err := Listen(path)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit Unix sockets")
		}
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v, want socket 0600", info.Mode())
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists after close: %v", err)
	}
}

func TestReadDeadlineReturnsTimeoutClass(t *testing.T) {
	server := testServer(HandlerFunc(func(context.Context, signing.Requester, ageprofile.UnwrapRequest) ([]byte, ErrorClass) {
		t.Fatal("handler called without a request")
		return nil, ClassInternal
	}))
	server.ReadTimeout = 20 * time.Millisecond
	serverConn, clientConn := net.Pipe()
	go server.serveConn(context.Background(), serverConn)
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	response, err := readFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	assertFailureClass(t, response, ClassTimeout)
	_ = clientConn.Close()
}

func testServer(handler Handler) *Server {
	return &Server{
		Handler:           handler,
		PeerUID:           func(net.Conn) (uint32, error) { return 7, nil },
		CurrentUID:        func() uint32 { return 7 },
		RequesterResolver: func(net.Conn) signing.Requester { return signing.Requester{Name: "test"} },
		DisconnectWatcher: func(ctx context.Context, _ net.Conn) { <-ctx.Done() },
	}
}

func testRequest(t *testing.T, recovery bool) ageprofile.UnwrapRequest {
	t.Helper()
	hardwarePrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var hardware ageprofile.PublicKey
	copy(hardware[:], hardwarePrivate.PublicKey().Bytes())
	var recoveryPublic *ageprofile.PublicKey
	if recovery {
		recoveryPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var value ageprofile.PublicKey
		copy(value[:], recoveryPrivate.PublicKey().Bytes())
		recoveryPublic = &value
	}
	recipient, err := ageprofile.NewRecipient(hardware, recoveryPublic)
	if err != nil {
		t.Fatal(err)
	}
	fileKey := []byte("0123456789abcdef")
	stanzas, err := recipient.Wrap(fileKey)
	clear(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	hardwareEnvelope, err := ageprofile.ParseEnvelope(stanzas[0])
	if err != nil {
		t.Fatal(err)
	}
	request := ageprofile.UnwrapRequest{
		ProfileID:     recipient.ProfileID(),
		HardwareKeyID: recipient.Hardware().ID,
		Hardware:      hardwareEnvelope,
	}
	if recovery {
		recoveryEnvelope, err := ageprofile.ParseEnvelope(stanzas[1])
		if err != nil {
			t.Fatal(err)
		}
		request.Recovery = &recoveryEnvelope
	}
	return request
}

func rawExchange(t *testing.T, server *Server, payload []byte) ([]byte, bool) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConn(context.Background(), serverConn)
		close(done)
	}()
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeFrame(clientConn, payload) }()
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	response, err := readFrame(clientConn)
	_ = clientConn.Close()
	<-done
	if writeErr := <-writeDone; writeErr != nil && err != nil {
		t.Fatalf("write request: %v", writeErr)
	}
	if err != nil {
		return nil, false
	}
	return response, true
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "yubitouch-ageipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type queueListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

type cancelAfterReadConn struct {
	net.Conn
	remaining int
	cancel    context.CancelFunc
	once      sync.Once
}

func (c *cancelAfterReadConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	c.remaining -= n
	if c.remaining <= 0 {
		c.once.Do(c.cancel)
	}
	return n, err
}

func newQueueListener() *queueListener {
	return &queueListener{connections: make(chan net.Conn, 4), closed: make(chan struct{})}
}

func (l *queueListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *queueListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *queueListener) Addr() net.Addr { return testAddr("ageipc") }

func (l *queueListener) deliver(conn net.Conn) error {
	select {
	case l.connections <- conn:
		return nil
	case <-l.closed:
		return net.ErrClosed
	}
}

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func assertFailureClass(t *testing.T, payload []byte, want ErrorClass) {
	t.Helper()
	key, err := unmarshalResponse(payload)
	clear(key)
	assertErrorClass(t, err, want)
}

func assertErrorClass(t *testing.T, err error, want ErrorClass) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want class %q", want)
	}
	got, ok := ClassOf(err)
	if !ok || got != want {
		t.Fatalf("error class = %q, %v; want %q", got, ok, want)
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

func TestFrameRejectsEmptyOversizedAndShortWrites(t *testing.T) {
	if err := writeFrame(io.Discard, nil); err == nil {
		t.Fatal("empty frame accepted")
	}
	if err := writeFrame(io.Discard, make([]byte, MaxFrameSize+1)); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if err := writeFrame(shortWriter{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v", err)
	}
}
