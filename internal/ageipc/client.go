package ageipc

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/mofelee/yubitouch/internal/ageprofile"
)

const defaultClientTimeout = 2 * time.Minute

// Client implements ageprofile.Client over the local YubiTouch daemon socket.
type Client struct {
	Path        string
	Timeout     time.Duration
	DialContext func(context.Context, string, string) (net.Conn, error)
}

var _ ageprofile.Client = (*Client)(nil)

// NewClient constructs a bounded local IPC client.
func NewClient(path string, timeout time.Duration) *Client {
	return &Client{Path: path, Timeout: timeout}
}

// Unwrap sends one validated request over one fresh Unix socket connection.
func (c *Client) Unwrap(ctx context.Context, request ageprofile.UnwrapRequest) ([]byte, error) {
	payload, err := marshalRequest(request)
	if err != nil {
		return nil, protocolError(ClassInvalidRequest)
	}
	defer clear(payload)
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := c.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	if c.Path == "" {
		return nil, protocolError(ClassDaemonUnavailable)
	}
	conn, err := dial(requestCtx, "unix", c.Path)
	if err != nil {
		return nil, contextClass(requestCtx, ClassDaemonUnavailable)
	}
	defer conn.Close()
	stopClose := context.AfterFunc(requestCtx, func() { _ = conn.Close() })
	defer stopClose()
	if deadline, ok := requestCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, protocolError(ClassDaemonUnavailable)
		}
	}
	if err := writeFrame(conn, payload); err != nil {
		return nil, contextClass(requestCtx, ClassDaemonUnavailable)
	}
	response, err := readFrame(conn)
	if err != nil {
		if errors.Is(err, errInvalidFrameSize) {
			return nil, protocolError(ClassProtocolFailure)
		}
		return nil, contextClass(requestCtx, ClassDaemonUnavailable)
	}
	defer clear(response)
	fileKey, err := unmarshalResponse(response)
	if !stopClose() || requestCtx.Err() != nil {
		clear(fileKey)
		return nil, contextClass(requestCtx, ClassCanceled)
	}
	if err != nil {
		return nil, err
	}
	return fileKey, nil
}

func contextClass(ctx context.Context, fallback ErrorClass) error {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return protocolError(ClassTimeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return protocolError(ClassCanceled)
	default:
		return protocolError(fallback)
	}
}
