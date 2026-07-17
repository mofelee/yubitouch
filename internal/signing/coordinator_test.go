package signing

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type eventRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *eventRecorder) Handle(event Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *eventRecorder) types() []EventType {
	r.mu.Lock()
	defer r.mu.Unlock()
	types := make([]EventType, len(r.events))
	for i := range r.events {
		types[i] = r.events[i].Type
	}
	return types
}

func TestCoordinatorSerializesSignatures(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	coordinator := New(nil, nil, time.Second)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := coordinator.Sign(context.Background(), func() (*ssh.Signature, error) {
				current := active.Add(1)
				for {
					old := maximum.Load()
					if current <= old || maximum.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				active.Add(-1)
				return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, 64)}, nil
			})
			if err != nil {
				t.Errorf("sign: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent signatures = %d, want 1", got)
	}
}

func TestCoordinatorPublishesLifecycle(t *testing.T) {
	recorder := &eventRecorder{}
	coordinator := New(nil, recorder, time.Second)
	_, err := coordinator.Sign(context.Background(), func() (*ssh.Signature, error) {
		return &ssh.Signature{Format: ssh.KeyAlgoED25519}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []EventType{EventInitializing, EventWaiting, EventSuccess}
	got := recorder.types()
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}

func TestCoordinatorTimesOutWithoutStartingNextRequest(t *testing.T) {
	blocked := make(chan struct{})
	coordinator := New(nil, nil, 10*time.Millisecond)
	_, err := coordinator.Sign(context.Background(), func() (*ssh.Signature, error) {
		<-blocked
		return nil, errors.New("stopped")
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want timeout", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = coordinator.Sign(ctx, func() (*ssh.Signature, error) {
		t.Fatal("second request started while first call was still active")
		return nil, nil
	})
	if !errors.Is(err, ErrTimeout) && !errors.Is(err, ErrCanceled) {
		t.Fatalf("second error = %v", err)
	}
	close(blocked)
}

func TestInitializerDeadlineIsNormalized(t *testing.T) {
	recorder := &eventRecorder{}
	coordinator := New(InitializerFunc(func(context.Context) error {
		return context.DeadlineExceeded
	}), recorder, time.Second)
	_, err := coordinator.Sign(context.Background(), func() (*ssh.Signature, error) {
		t.Fatal("sign call ran after initializer deadline")
		return nil, nil
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if got := coordinator.LastEvent().Type; got != EventTimeout {
		t.Fatalf("last event = %s", got)
	}
}

func TestQueuedCancellationDoesNotPublishLifecycle(t *testing.T) {
	recorder := &eventRecorder{}
	coordinator := New(nil, recorder, time.Second)
	started := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		_, err := coordinator.Sign(context.Background(), func() (*ssh.Signature, error) {
			close(started)
			<-release
			return &ssh.Signature{Format: ssh.KeyAlgoED25519}, nil
		})
		firstResult <- err
	}()
	<-started

	queuedCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := coordinator.Sign(queuedCtx, func() (*ssh.Signature, error) {
		t.Fatal("canceled queued request started")
		return nil, nil
	})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("queued error = %v", err)
	}
	got := recorder.types()
	want := []EventType{EventInitializing, EventWaiting}
	if len(got) != len(want) {
		t.Fatalf("events after queued cancellation = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events after queued cancellation = %v", got)
		}
	}

	close(release)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
}
