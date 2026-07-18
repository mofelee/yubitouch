package ui

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/native/macos"
)

type App struct {
	sound         string
	cancelHandler func(uint64) bool
	consumeCancel func() uint64
}

func New(sound string) *App {
	return &App{sound: sound, consumeCancel: macos.ConsumeCancelRequest}
}

func (a *App) SetCancelHandler(handler func(uint64) bool) {
	a.cancelHandler = handler
}

func (a *App) Handle(event signing.Event) {
	name := requesterName(event.Requester)
	switch event.Type {
	case signing.EventWaiting:
		macos.ShowWaiting(a.sound, name+" 正在请求 SSH 签名", waitingSubtitle(event.Requester), event.Requester.BundleIdentifier, event.RequestID)
	case signing.EventSuccess:
		macos.ShowSuccess(name+" 的请求已授权", event.Requester.BundleIdentifier, event.RequestID)
	case signing.EventTimeout:
		macos.ShowFailure(name+" 的请求超时", "签名等待超时，请重试", event.Requester.BundleIdentifier, event.RequestID)
	case signing.EventCanceled:
		macos.Hide(event.RequestID)
	case signing.EventFailure:
		macos.ShowFailure(name+" 的请求失败", signFailureMessage(event.Err), event.Requester.BundleIdentifier, event.RequestID)
	}
}

func requesterName(requester signing.Requester) string {
	if name := strings.TrimSpace(requester.Name); name != "" {
		return name
	}
	if direct := strings.TrimSpace(requester.DirectClient); direct != "" {
		return direct
	}
	return "未知程序"
}

func waitingSubtitle(requester signing.Requester) string {
	direct := strings.TrimSpace(requester.DirectClient)
	if direct == "" || strings.EqualFold(direct, requesterName(requester)) {
		return "请触摸 YubiKey"
	}
	return "请触摸 YubiKey · 直接客户端 " + direct
}

func signFailureMessage(err error) string {
	if errors.Is(err, signing.ErrDeviceUnavailable) {
		return "YubiKey 已断开，请重新连接"
	}
	return "签名失败，请检查 YubiKey 后重试"
}

func (a *App) Run(ctx context.Context, serverResult <-chan error) error {
	macos.InitializeApplication()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if a.cancelHandler != nil {
		go a.watchCancellation(runCtx)
	}
	result := make(chan error, 1)
	go func() {
		select {
		case err := <-serverResult:
			result <- err
		case <-ctx.Done():
			result <- nil
		}
		macos.StopApplication()
	}()
	macos.RunApplication()
	return <-result
}

func (a *App) watchCancellation(ctx context.Context) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.consumeCancel != nil {
				if requestID := a.consumeCancel(); requestID != 0 {
					a.cancelHandler(requestID)
				}
			}
		}
	}
}

type MultiSink []signing.Sink

func (m MultiSink) Handle(event signing.Event) {
	for _, sink := range m {
		if sink != nil {
			sink.Handle(event)
		}
	}
}

func IsPromptUnavailable(err error) bool {
	return errors.Is(err, macos.ErrPromptUnavailable)
}
