package ui

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCancellationWatcherConsumesSignalOnce(t *testing.T) {
	app := New("none")
	var requestID atomic.Uint64
	requestID.Store(42)
	app.consumeCancel = func() uint64 { return requestID.Swap(0) }
	handled := make(chan struct{}, 1)
	app.SetCancelHandler(func(got uint64) bool {
		if got != 42 {
			t.Errorf("request ID = %d, want 42", got)
		}
		handled <- struct{}{}
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.watchCancellation(ctx)
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("cancel signal was not handled")
	}
	select {
	case <-handled:
		t.Fatal("cancel signal was handled more than once")
	case <-time.After(100 * time.Millisecond):
	}
}
