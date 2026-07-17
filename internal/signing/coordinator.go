package signing

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrCanceled = errors.New("sign request canceled")
	ErrTimeout  = errors.New("sign request timed out")
)

type EventType string

const (
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

type InitializerFunc func(context.Context) error

func (f InitializerFunc) Ensure(ctx context.Context) error {
	return f(ctx)
}

type Result struct {
	Signature *ssh.Signature
	Err       error
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
	return c.SignCancelable(ctx, call, nil)
}

func (c *Coordinator) SignCancelable(ctx context.Context, call func() (*ssh.Signature, error), cancelCall func()) (*ssh.Signature, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	select {
	case c.semaphore <- struct{}{}:
	case <-ctx.Done():
		return nil, contextError(ctx)
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	activeID := c.beginActive(cancelRequest)
	defer func() {
		cancelRequest()
		c.endActive(activeID)
	}()
	var cancelOnce sync.Once
	cancelOperation := func() {
		cancelOnce.Do(func() {
			if cancelCall != nil {
				cancelCall()
			}
		})
	}

	result := make(chan Result, 1)
	go func() {
		defer func() { <-c.semaphore }()
		c.publish(Event{Type: EventInitializing, At: c.now(), RequestID: activeID})
		if err := c.initializer.Ensure(requestCtx); err != nil {
			result <- Result{Err: err}
			return
		}
		if err := requestCtx.Err(); err != nil {
			result <- Result{Err: err}
			return
		}
		c.publish(Event{Type: EventWaiting, At: c.now(), RequestID: activeID})
		sig, err := call()
		if err != nil {
			if invalidator, ok := c.initializer.(Invalidator); ok {
				invalidator.Invalidate()
			}
		}
		result <- Result{Signature: sig, Err: err}
	}()

	select {
	case got := <-result:
		if got.Err != nil {
			if errors.Is(got.Err, context.DeadlineExceeded) {
				cancelOperation()
				err := ErrTimeout
				c.publish(Event{Type: EventTimeout, At: c.now(), Err: err, RequestID: activeID})
				return nil, err
			}
			if errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
				cancelOperation()
				return nil, c.finishContext(requestCtx, activeID)
			}
			if errors.Is(got.Err, context.Canceled) {
				cancelOperation()
				return nil, c.finishContext(requestCtx, activeID)
			}
			if errors.Is(requestCtx.Err(), context.Canceled) {
				cancelOperation()
				return nil, c.finishContext(requestCtx, activeID)
			}
			c.publish(Event{Type: EventFailure, At: c.now(), Err: got.Err, RequestID: activeID})
			return nil, got.Err
		}
		c.publish(Event{Type: EventSuccess, At: c.now(), RequestID: activeID})
		return got.Signature, nil
	case <-requestCtx.Done():
		cancelOperation()
		return nil, c.finishContext(requestCtx, activeID)
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

func (c *Coordinator) finishContext(ctx context.Context, requestID uint64) error {
	err := contextError(ctx)
	if errors.Is(err, ErrTimeout) {
		c.publish(Event{Type: EventTimeout, At: c.now(), Err: err, RequestID: requestID})
		return err
	}
	c.publish(Event{Type: EventCanceled, At: c.now(), Err: err, RequestID: requestID})
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
