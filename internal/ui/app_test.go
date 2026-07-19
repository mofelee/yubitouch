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

func TestRequesterTextKeepsTouchInstructionAndDirectClient(t *testing.T) {
	requester := signing.Requester{Name: "Terminal", DirectClient: "ssh"}
	if got := requesterName(requester); got != "Terminal" {
		t.Fatalf("requester name = %q", got)
	}
	if got := waitingSubtitle(requester, signing.SignerYubiKey); got != "请触摸 YubiKey · 直接客户端 ssh" {
		t.Fatalf("waiting subtitle = %q", got)
	}
}

func TestRequesterTextUsesStableFallback(t *testing.T) {
	if got := requesterName(signing.Requester{}); got != "未知程序" {
		t.Fatalf("requester fallback = %q", got)
	}
	if got := waitingSubtitle(signing.Requester{Name: "YubiTouch", DirectClient: "YubiTouch"}, signing.SignerYubiKey); got != "请触摸 YubiKey" {
		t.Fatalf("same-client subtitle = %q", got)
	}
}

func TestFallbackSubtitleDoesNotRequestYubiKeyTouch(t *testing.T) {
	got := waitingSubtitle(signing.Requester{Name: "Terminal", DirectClient: "ssh"}, signing.Signer1Password)
	if got != "YubiKey 未连接 · 使用 1Password" {
		t.Fatalf("fallback subtitle = %q", got)
	}
}

func TestFallbackFailureMessagesAreExplicit(t *testing.T) {
	if got := signFailureMessage(signing.ErrFallbackUnavailable); got != "1Password fallback 不可用，请解锁并检查 SSH Agent" {
		t.Fatalf("fallback failure message = %q", got)
	}
	if got := signFailureMessage(signing.ErrFallbackKeyUnavailable); got != "1Password 中未找到配置的 SSH key" {
		t.Fatalf("fallback key message = %q", got)
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
