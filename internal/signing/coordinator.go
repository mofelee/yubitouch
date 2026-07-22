package signing

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrCanceled          = errors.New("sign request canceled")
	ErrTimeout           = errors.New("sign request timed out")
	ErrDeviceUnavailable = errors.New("YubiKey became unavailable during signing")
)

type EventType string

type Operation string

const (
	OperationSSHSign    Operation = "ssh_sign"
	OperationAgeDecrypt Operation = "age_decrypt"

	EventInitializing EventType = "initializing"
	EventWaiting      EventType = "waiting_for_touch"
	EventSuccess      EventType = "success"
	EventFailure      EventType = "failure"
	EventTimeout      EventType = "timeout"
	EventCanceled     EventType = "canceled"
)

type Event struct {
	Type      EventType
	At        time.Time
	Err       error
	RequestID uint64
	Requester Requester
	Operation Operation
}

type Sink interface {
	Handle(Event)
}

type Initializer interface {
	Ensure(context.Context) error
}

type Invalidator interface {
	Invalidate()
}

type SignFailureNormalizer interface {
	NormalizeSignFailure(context.Context, error) error
}

type InitializerFunc func(context.Context) error

func (f InitializerFunc) Ensure(ctx context.Context) error {
	return f(ctx)
}

type Result struct {
	Signature *ssh.Signature
	Err       error
}

// requestEvents serializes progress and terminal delivery for one request.
// Once a terminal event wins the gate, delayed worker progress is discarded.
type requestEvents struct {
	mu       sync.Mutex
	terminal bool
}

func (e *requestEvents) publishProgress(ctx context.Context, coordinator *Coordinator, event Event) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.terminal || ctx.Err() != nil {
		return false
	}
	coordinator.publish(event)
	return true
}

func (e *requestEvents) publishTerminal(coordinator *Coordinator, event Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.terminal {
		return
	}
	e.terminal = true
	coordinator.publish(event)
}

type Coordinator struct {
	initializer Initializer
	sink        Sink
	timeout     time.Duration
	semaphore   chan struct{}
	now         func() time.Time

	stateMu sync.RWMutex
	last    Event

	activeMu   sync.Mutex
	activeID   uint64
	activeNext uint64
	activeStop context.CancelFunc
}

func New(initializer Initializer, sink Sink, timeout time.Duration) *Coordinator {
	if initializer == nil {
		initializer = InitializerFunc(func(context.Context) error { return nil })
	}
	if sink == nil {
		sink = discardSink{}
	}
	return &Coordinator{
		initializer: initializer,
		sink:        sink,
		timeout:     timeout,
		semaphore:   make(chan struct{}, 1),
		now:         time.Now,
	}
}

func (c *Coordinator) Sign(ctx context.Context, call func() (*ssh.Signature, error)) (*ssh.Signature, error) {
	return c.SignCancelableFor(ctx, Requester{}, call, nil)
}

func (c *Coordinator) SignCancelable(ctx context.Context, call func() (*ssh.Signature, error), cancelCall func()) (*ssh.Signature, error) {
	return c.SignCancelableFor(ctx, Requester{}, call, cancelCall)
}

func (c *Coordinator) SignFor(ctx context.Context, requester Requester, call func() (*ssh.Signature, error)) (*ssh.Signature, error) {
	return c.SignCancelableFor(ctx, requester, call, nil)
}

func (c *Coordinator) SignCancelableFor(ctx context.Context, requester Requester, call func() (*ssh.Signature, error), cancelCall func()) (*ssh.Signature, error) {
	signatureResult := make(chan *ssh.Signature, 1)
	err := c.RunCancelableFor(
		ctx,
		requester,
		OperationSSHSign,
		c.initializer,
		func() error {
			signature, err := call()
			signatureResult <- signature
			return err
		},
		cancelCall,
	)
	if err != nil {
		return nil, err
	}
	return <-signatureResult, nil
}

// RunCancelableFor serializes a non-signing PIV operation with SSH signing.
// The semaphore remains held until call returns, even if the caller times out.
func (c *Coordinator) RunCancelableFor(
	ctx context.Context,
	requester Requester,
	operation Operation,
	initializer Initializer,
	call func() error,
	cancelCall func(),
) error {
	if operation == "" {
		operation = OperationSSHSign
	}
	if initializer == nil {
		initializer = InitializerFunc(func(context.Context) error { return nil })
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	select {
	case c.semaphore <- struct{}{}:
	case <-ctx.Done():
		return contextError(ctx)
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	activeID := c.beginActive(cancelRequest)
	defer func() {
		cancelRequest()
		c.endActive(activeID)
	}()
	var cancelOnce sync.Once
	events := &requestEvents{}
	cancelOperation := func() {
		cancelOnce.Do(func() {
			if cancelCall != nil {
				cancelCall()
			}
		})
	}

	result := make(chan error, 1)
	go func() {
		defer func() { <-c.semaphore }()
		if !events.publishProgress(requestCtx, c, Event{Type: EventInitializing, At: c.now(), RequestID: activeID, Requester: requester, Operation: operation}) {
			result <- requestCtx.Err()
			return
		}
		if err := initializer.Ensure(requestCtx); err != nil {
			result <- err
			return
		}
		if err := requestCtx.Err(); err != nil {
			result <- err
			return
		}
		if !events.publishProgress(requestCtx, c, Event{Type: EventWaiting, At: c.now(), RequestID: activeID, Requester: requester, Operation: operation}) {
			result <- requestCtx.Err()
			return
		}
		if err := requestCtx.Err(); err != nil {
			result <- err
			return
		}
		err := call()
		if err != nil {
			if normalizer, ok := initializer.(SignFailureNormalizer); ok {
				err = normalizer.NormalizeSignFailure(requestCtx, err)
			}
			if invalidator, ok := initializer.(Invalidator); ok {
				invalidator.Invalidate()
			}
		}
		result <- err
	}()

	select {
	case gotErr := <-result:
		if gotErr != nil {
			if errors.Is(gotErr, context.DeadlineExceeded) {
				cancelOperation()
				err := ErrTimeout
				events.publishTerminal(c, Event{Type: EventTimeout, At: c.now(), Err: err, RequestID: activeID, Requester: requester, Operation: operation})
				return err
			}
			if errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
				cancelOperation()
				return c.finishContext(requestCtx, activeID, requester, operation, events)
			}
			if errors.Is(gotErr, context.Canceled) {
				cancelOperation()
				return c.finishContext(requestCtx, activeID, requester, operation, events)
			}
			if errors.Is(requestCtx.Err(), context.Canceled) {
				cancelOperation()
				return c.finishContext(requestCtx, activeID, requester, operation, events)
			}
			events.publishTerminal(c, Event{Type: EventFailure, At: c.now(), Err: gotErr, RequestID: activeID, Requester: requester, Operation: operation})
			return gotErr
		}
		if requestCtx.Err() != nil {
			cancelOperation()
			return c.finishContext(requestCtx, activeID, requester, operation, events)
		}
		events.publishTerminal(c, Event{Type: EventSuccess, At: c.now(), RequestID: activeID, Requester: requester, Operation: operation})
		return nil
	case <-requestCtx.Done():
		cancelOperation()
		return c.finishContext(requestCtx, activeID, requester, operation, events)
	}
}

func (c *Coordinator) CancelCurrent() bool {
	c.activeMu.Lock()
	id := c.activeID
	c.activeMu.Unlock()
	return c.Cancel(id)
}

func (c *Coordinator) Cancel(id uint64) bool {
	if id == 0 {
		return false
	}
	c.activeMu.Lock()
	if c.activeID != id {
		c.activeMu.Unlock()
		return false
	}
	cancel := c.activeStop
	c.activeID = 0
	c.activeStop = nil
	c.activeMu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

func (c *Coordinator) LastEvent() Event {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.last
}

func (c *Coordinator) finishContext(
	ctx context.Context,
	requestID uint64,
	requester Requester,
	operation Operation,
	events *requestEvents,
) error {
	err := contextError(ctx)
	if errors.Is(err, ErrTimeout) {
		events.publishTerminal(c, Event{Type: EventTimeout, At: c.now(), Err: err, RequestID: requestID, Requester: requester, Operation: operation})
		return err
	}
	events.publishTerminal(c, Event{Type: EventCanceled, At: c.now(), Err: err, RequestID: requestID, Requester: requester, Operation: operation})
	return err
}

func (c *Coordinator) beginActive(cancel context.CancelFunc) uint64 {
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	c.activeNext++
	c.activeID = c.activeNext
	c.activeStop = cancel
	return c.activeID
}

func (c *Coordinator) endActive(id uint64) {
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	if c.activeID == id {
		c.activeID = 0
		c.activeStop = nil
	}
}

func contextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrCanceled
}

func (c *Coordinator) publish(event Event) {
	c.stateMu.Lock()
	c.last = event
	c.stateMu.Unlock()
	c.sink.Handle(event)
}

type discardSink struct{}

func (discardSink) Handle(Event) {}
