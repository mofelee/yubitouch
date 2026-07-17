package ui

import (
	"context"
	"errors"

	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/native/macos"
)

type App struct {
	sound string
}

func New(sound string) *App {
	return &App{sound: sound}
}

func (a *App) Handle(event signing.Event) {
	switch event.Type {
	case signing.EventWaiting:
		macos.ShowWaiting(a.sound)
	case signing.EventSuccess:
		macos.ShowSuccess()
	case signing.EventTimeout:
		macos.ShowFailure("签名等待超时，请重试")
	case signing.EventFailure:
		macos.ShowFailure("签名失败，请检查 YubiKey 后重试")
	}
}

func (a *App) Run(ctx context.Context, serverResult <-chan error) error {
	macos.InitializeApplication()
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
