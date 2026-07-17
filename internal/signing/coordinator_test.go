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

type normalizingInitializer struct {
	normalized error
}

func (n normalizingInitializer) Ensure(context.Context) error { return nil }
func (n normalizingInitializer) NormalizeSignFailure(context.Context, error) error {
	return n.normalized
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

func TestCoordinatorPublishesNormalizedSignFailure(t *testing.T) {
	recorder := &eventRecorder{}
	coordinator := New(normalizingInitializer{normalized: ErrDeviceUnavailable}, recorder, time.Second)
	_, err := coordinator.Sign(context.Background(), func() (*ssh.Signature, error) {
		return nil, errors.New("opaque agent failure")
	})
	if !errors.Is(err, ErrDeviceUnavailable) {
		t.Fatalf("error = %v, want device unavailable", err)
	}
	event := coordinator.LastEvent()
	if event.Type != EventFailure || !errors.Is(event.Err, ErrDeviceUnavailable) {
		t.Fatalf("last event = %+v", event)
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

func TestCancelCurrentStopsActiveRequestOnce(t *testing.T) {
	recorder := &eventRecorder{}
	coordinator := New(nil, recorder, time.Second)
	started := make(chan struct{})
	stopped := make(chan struct{})
	var stopOnce sync.Once
	result := make(chan error, 1)
	go func() {
		_, err := coordinator.SignCancelable(
			context.Background(),
			func() (*ssh.Signature, error) {
				close(started)
				<-stopped
				return nil, errors.New("backend connection closed")
			},
			func() { stopOnce.Do(func() { close(stopped) }) },
		)
		result <- err
	}()
	<-started
	if !coordinator.CancelCurrent() {
		t.Fatal("active request was not canceled")
	}
	if coordinator.CancelCurrent() {
		t.Fatal("duplicate cancellation affected the active request")
	}
	if err := <-result; !errors.Is(err, ErrCanceled) {
		t.Fatalf("cancel error = %v, want ErrCanceled", err)
	}
	want := []EventType{EventInitializing, EventWaiting, EventCanceled}
	if got := recorder.types(); !eventTypesEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestCancelCurrentDoesNotCancelNextRequest(t *testing.T) {
	coordinator := New(nil, nil, time.Second)
	firstStarted := make(chan struct{})
	firstStopped := make(chan struct{})
	var stopOnce sync.Once
	firstResult := make(chan error, 1)
	go func() {
		_, err := coordinator.SignCancelable(
			context.Background(),
			func() (*ssh.Signature, error) {
				close(firstStarted)
				<-firstStopped
				return nil, errors.New("backend connection closed")
			},
			func() { stopOnce.Do(func() { close(firstStopped) }) },
		)
		firstResult <- err
	}()
	<-firstStarted
	firstID := currentRequestID(coordinator)

	secondStarted := make(chan struct{})
	secondRelease := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		_, err := coordinator.Sign(context.Background(), func() (*ssh.Signature, error) {
			close(secondStarted)
			<-secondRelease
			return &ssh.Signature{Format: ssh.KeyAlgoED25519}, nil
		})
		secondResult <- err
	}()
	if !coordinator.CancelCurrent() {
		t.Fatal("first request was not canceled")
	}
	if err := <-firstResult; !errors.Is(err, ErrCanceled) {
		t.Fatalf("first error = %v", err)
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second request did not start after cancellation")
	}
	secondID := currentRequestID(coordinator)
	if firstID == 0 || secondID == 0 || firstID == secondID {
		t.Fatalf("request IDs first=%d second=%d", firstID, secondID)
	}
	if coordinator.Cancel(firstID) {
		t.Fatal("stale request ID canceled the next request")
	}
	close(secondRelease)
	if err := <-secondResult; err != nil {
		t.Fatalf("second request failed: %v", err)
	}
}

func currentRequestID(coordinator *Coordinator) uint64 {
	coordinator.activeMu.Lock()
	defer coordinator.activeMu.Unlock()
	return coordinator.activeID
}

func TestConcurrentCancelAndSuccessPublishOneTerminalEvent(t *testing.T) {
	for range 50 {
		recorder := &eventRecorder{}
		coordinator := New(nil, recorder, time.Second)
		started := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		result := make(chan error, 1)
		go func() {
			_, err := coordinator.SignCancelable(
				context.Background(),
				func() (*ssh.Signature, error) {
					close(started)
					<-release
					return &ssh.Signature{Format: ssh.KeyAlgoED25519}, nil
				},
				func() { releaseOnce.Do(func() { close(release) }) },
			)
			result <- err
		}()
		<-started
		var actions sync.WaitGroup
		actions.Add(2)
		go func() {
			defer actions.Done()
			coordinator.CancelCurrent()
		}()
		go func() {
			defer actions.Done()
			releaseOnce.Do(func() { close(release) })
		}()
		actions.Wait()
		<-result

		terminalCount := 0
		for _, eventType := range recorder.types() {
			switch eventType {
			case EventSuccess, EventFailure, EventTimeout, EventCanceled:
				terminalCount++
			}
		}
		if terminalCount != 1 {
			t.Fatalf("terminal event count = %d, events = %v", terminalCount, recorder.types())
		}
	}
}

func eventTypesEqual(got []EventType, want []EventType) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
