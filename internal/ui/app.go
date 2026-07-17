package ui

import (
	"context"
	"errors"
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
	switch event.Type {
	case signing.EventWaiting:
		macos.ShowWaiting(a.sound, event.RequestID)
	case signing.EventSuccess:
		macos.ShowSuccess(event.RequestID)
	case signing.EventTimeout:
		macos.ShowFailure("签名等待超时，请重试", event.RequestID)
	case signing.EventCanceled:
		macos.Hide(event.RequestID)
	case signing.EventFailure:
		macos.ShowFailure(signFailureMessage(event.Err), event.RequestID)
	}
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
