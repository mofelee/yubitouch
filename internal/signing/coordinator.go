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
)

type Event struct {
	Type EventType
	At   time.Time
	Err  error
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
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	select {
	case c.semaphore <- struct{}{}:
	case <-ctx.Done():
		return nil, c.finishContext(ctx)
	}

	result := make(chan Result, 1)
	go func() {
		defer func() { <-c.semaphore }()
		c.publish(Event{Type: EventInitializing, At: c.now()})
		if err := c.initializer.Ensure(ctx); err != nil {
			result <- Result{Err: err}
			return
		}
		if err := ctx.Err(); err != nil {
			result <- Result{Err: err}
			return
		}
		c.publish(Event{Type: EventWaiting, At: c.now()})
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
				err := ErrTimeout
				c.publish(Event{Type: EventTimeout, At: c.now(), Err: err})
				return nil, err
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, c.finishContext(ctx)
			}
			if errors.Is(got.Err, context.Canceled) {
				err := ErrCanceled
				c.publish(Event{Type: EventFailure, At: c.now(), Err: err})
				return nil, err
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, c.finishContext(ctx)
			}
			c.publish(Event{Type: EventFailure, At: c.now(), Err: got.Err})
			return nil, got.Err
		}
		c.publish(Event{Type: EventSuccess, At: c.now()})
		return got.Signature, nil
	case <-ctx.Done():
		return nil, c.finishContext(ctx)
	}
}

func (c *Coordinator) LastEvent() Event {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.last
}

func (c *Coordinator) finishContext(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err := ErrTimeout
		c.publish(Event{Type: EventTimeout, At: c.now(), Err: err})
		return err
	}
	err := ErrCanceled
	c.publish(Event{Type: EventFailure, At: c.now(), Err: err})
	return err
}

func (c *Coordinator) publish(event Event) {
	c.stateMu.Lock()
	c.last = event
	c.stateMu.Unlock()
	c.sink.Handle(event)
}

type discardSink struct{}

func (discardSink) Handle(Event) {}
