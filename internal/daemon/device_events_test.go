package daemon

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/config"
)

func TestNeedsYubiKeyMonitor(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{name: "disabled", cfg: config.Config{}, want: false},
		{name: "fallback", cfg: config.Config{FallbackAgent: config.FallbackAgent1Password}, want: true},
		{name: "age", cfg: config.Config{Age: &config.AgeConfig{}}, want: true},
		{
			name: "age and fallback",
			cfg: config.Config{
				Age:           &config.AgeConfig{},
				FallbackAgent: config.FallbackAgent1Password,
			},
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := needsYubiKeyMonitor(test.cfg); got != test.want {
				t.Fatalf("needsYubiKeyMonitor() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestFanOutDeviceEventsDoesNotBlockOnSlowConsumers(t *testing.T) {
	source := make(chan struct{})
	streams := fanOutDeviceEvents(source)
	if cap(streams.Router) != 1 || cap(streams.Age) != 1 {
		t.Fatalf("event stream capacities = router:%d age:%d, want 1 each", cap(streams.Router), cap(streams.Age))
	}

	sent := make(chan struct{})
	go func() {
		defer close(sent)
		defer close(source)
		for range 1024 {
			source <- struct{}{}
		}
	}()
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("fan-out blocked while both consumers were slow")
	}

	assertEventsThenClosed(t, streams.Router)
	assertEventsThenClosed(t, streams.Age)
}

func TestFanOutDeviceEventsKeepsConsumersIndependent(t *testing.T) {
	source := make(chan struct{})
	streams := fanOutDeviceEvents(source)

	source <- struct{}{}
	assertDeviceEvent(t, streams.Router)
	// Leave Age unread. Router must still receive a later event.
	source <- struct{}{}
	assertDeviceEvent(t, streams.Router)
	assertDeviceEvent(t, streams.Age)
	close(source)
	assertEventStreamClosed(t, streams.Router)
	assertEventStreamClosed(t, streams.Age)
}

func TestFanOutDeviceEventsPropagatesSourceClosure(t *testing.T) {
	source := make(chan struct{})
	streams := fanOutDeviceEvents(source)
	close(source)
	assertEventStreamClosed(t, streams.Router)
	assertEventStreamClosed(t, streams.Age)
}

func TestFanOutDeviceEventsLeavesNilSourceDisabled(t *testing.T) {
	streams := fanOutDeviceEvents(nil)
	if streams.Router != nil || streams.Age != nil {
		t.Fatalf("nil source streams = %+v, want nil outputs", streams)
	}
}

func TestAgeHardwareSessionWatcherInvalidatesEveryDeviceEventAndClosesOnSourceClosure(t *testing.T) {
	events := make(chan struct{})
	sessions := newRecordingAgeHardwareSessions()
	watcher := startAgeHardwareSessionWatcher(events, sessions)

	for range 2 {
		events <- struct{}{}
		select {
		case <-sessions.invalidated:
		case <-time.After(time.Second):
			t.Fatal("device event did not invalidate the hardware session")
		}
	}
	close(events)
	if err := watcher.stop(); err != nil {
		t.Fatal(err)
	}
	invalidations, closes := sessions.counts()
	if invalidations != 2 || closes != 1 {
		t.Fatalf("session lifecycle = invalidations:%d closes:%d, want 2 and 1", invalidations, closes)
	}
}

func TestAgeHardwareSessionWatcherShutdownWaitsForManagerReap(t *testing.T) {
	sessions := newRecordingAgeHardwareSessions()
	sessions.closeGate = make(chan struct{})
	watcher := startAgeHardwareSessionWatcher(nil, sessions)
	done := make(chan error, 1)
	go func() { done <- watcher.stop() }()

	select {
	case <-sessions.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not close the hardware manager")
	}
	select {
	case <-done:
		t.Fatal("shutdown returned before the hardware manager reaped its helper")
	default:
	}
	close(sessions.closeGate)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after helper reap")
	}
	if err := watcher.stop(); err != nil {
		t.Fatal(err)
	}
	_, closes := sessions.counts()
	if closes != 1 {
		t.Fatalf("manager closed %d times, want once", closes)
	}
}

func TestAgeHardwareSessionWatcherReturnsManagerCloseError(t *testing.T) {
	want := errors.New("close failed")
	sessions := newRecordingAgeHardwareSessions()
	sessions.closeErr = want
	watcher := startAgeHardwareSessionWatcher(nil, sessions)
	if err := watcher.stop(); !errors.Is(err, want) {
		t.Fatalf("stop error = %v, want %v", err, want)
	}
}

func TestAgeHardwareSessionWatcherReturnsInvalidationErrorAndClosesManager(t *testing.T) {
	want := errors.New("helper was not reaped")
	events := make(chan struct{})
	sessions := newRecordingAgeHardwareSessions()
	sessions.invalidateErr = want
	watcher := startAgeHardwareSessionWatcher(events, sessions)
	events <- struct{}{}
	if err := watcher.stop(); !errors.Is(err, want) {
		t.Fatalf("stop error = %v, want %v", err, want)
	}
	invalidations, closes := sessions.counts()
	if invalidations != 1 || closes != 1 {
		t.Fatalf("session lifecycle = invalidations:%d closes:%d, want 1 and 1", invalidations, closes)
	}
}

func TestAgeHardwareInvalidatorBindsDaemonManager(t *testing.T) {
	if invalidator := ageHardwareInvalidator(nil); invalidator != nil {
		t.Fatal("nil hardware manager produced an invalidator")
	}
	sessions := newRecordingAgeHardwareSessions()
	invalidator := ageHardwareInvalidator(sessions)
	if invalidator == nil {
		t.Fatal("hardware manager did not produce an invalidator")
	}
	if err := invalidator(); err != nil {
		t.Fatal(err)
	}
	invalidations, closes := sessions.counts()
	if invalidations != 1 || closes != 0 {
		t.Fatalf("session lifecycle = invalidations:%d closes:%d, want 1 and 0", invalidations, closes)
	}
}

type recordingAgeHardwareSessions struct {
	mu            sync.Mutex
	invalidates   int
	closes        int
	invalidated   chan struct{}
	closeStarted  chan struct{}
	closeGate     chan struct{}
	invalidateErr error
	closeErr      error
	closeOnce     sync.Once
}

func newRecordingAgeHardwareSessions() *recordingAgeHardwareSessions {
	return &recordingAgeHardwareSessions{
		invalidated:  make(chan struct{}, 8),
		closeStarted: make(chan struct{}),
	}
}

func (s *recordingAgeHardwareSessions) Invalidate() error {
	s.mu.Lock()
	s.invalidates++
	s.mu.Unlock()
	s.invalidated <- struct{}{}
	return s.invalidateErr
}

func (s *recordingAgeHardwareSessions) Close() error {
	s.mu.Lock()
	s.closes++
	s.mu.Unlock()
	s.closeOnce.Do(func() { close(s.closeStarted) })
	if s.closeGate != nil {
		<-s.closeGate
	}
	return s.closeErr
}

func (s *recordingAgeHardwareSessions) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.invalidates, s.closes
}

func assertEventsThenClosed(t *testing.T, events <-chan struct{}) {
	t.Helper()
	count := 0
	for {
		select {
		case _, ok := <-events:
			if !ok {
				if count == 0 {
					t.Fatal("event stream closed without delivering an event")
				}
				return
			}
			count++
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for device event stream to close")
		}
	}
}

func assertDeviceEvent(t *testing.T, events <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-events:
		if !ok {
			t.Fatal("event stream closed before delivering an event")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for device event")
	}
}

func assertEventStreamClosed(t *testing.T, events <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("received unexpected device event")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for device event stream to close")
	}
}
