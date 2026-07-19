//go:build !darwin || !cgo

package macos

import "errors"

var ErrPromptUnavailable = errors.New("native PIN prompt is unavailable")
var ErrPromptCanceled = errors.New("PIN prompt was canceled")

func InitializeApplication() {}
func RunApplication()        {}
func StopApplication()       {}
func ShowWaiting(string, string, string, string, bool, uint64) {
}
func ShowSuccess(string, string, uint64) {
}
func ShowFailure(string, string, string, uint64) {
}
func Hide(uint64)                  {}
func ConsumeCancelRequest() uint64 { return 0 }
func ShowAbout()                   {}
func PromptPIN() ([]byte, error) {
	return nil, ErrPromptUnavailable
}
