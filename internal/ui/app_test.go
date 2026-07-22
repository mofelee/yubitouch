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

func TestOperationTextDistinguishesAgeDecrypt(t *testing.T) {
	if got := operationAction(signing.OperationAgeDecrypt); got != "age 解密" {
		t.Fatalf("age action = %q", got)
	}
	if got := operationFailureMessage(signing.OperationAgeDecrypt, errors.New("opaque")); got != "age 解密失败，请检查 YubiKey 后重试" {
		t.Fatalf("age failure = %q", got)
	}
	if got := operationAction(signing.OperationSSHSign); got != "SSH 签名" {
		t.Fatalf("SSH action = %q", got)
	}
}

func TestRequesterTextKeepsTouchInstructionAndDirectClient(t *testing.T) {
	requester := signing.Requester{Name: "Terminal", DirectClient: "ssh"}
	if got := requesterName(requester); got != "Terminal" {
		t.Fatalf("requester name = %q", got)
	}
	if got := waitingSubtitle(requester); got != "请触摸 YubiKey · 直接客户端 ssh" {
		t.Fatalf("waiting subtitle = %q", got)
	}
}

func TestRequesterTextUsesStableFallback(t *testing.T) {
	if got := requesterName(signing.Requester{}); got != "未知程序" {
		t.Fatalf("requester fallback = %q", got)
	}
	if got := waitingSubtitle(signing.Requester{Name: "YubiTouch", DirectClient: "YubiTouch"}); got != "请触摸 YubiKey" {
		t.Fatalf("same-client subtitle = %q", got)
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
