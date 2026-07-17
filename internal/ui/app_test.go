package ui

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/signing"
)

func TestSignFailureMessageDistinguishesRemovedDevice(t *testing.T) {
	if got := signFailureMessage(signing.ErrDeviceUnavailable); got != "YubiKey 已断开，请重新连接" {
		t.Fatalf("device failure message = %q", got)
	}
	if got := signFailureMessage(errors.New("other failure")); got != "签名失败，请检查 YubiKey 后重试" {
		t.Fatalf("generic failure message = %q", got)
	}
}

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
