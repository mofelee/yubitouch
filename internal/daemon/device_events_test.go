package daemon

import (
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
