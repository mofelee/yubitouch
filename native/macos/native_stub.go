//go:build !darwin || !cgo

package macos

import "errors"

var ErrPromptUnavailable = errors.New("native PIN prompt is unavailable")
var ErrPromptCanceled = errors.New("PIN prompt was canceled")

func InitializeApplication() {}
func RunApplication()        {}
func StopApplication()       {}
func ShowWaiting(string)     {}
func ShowSuccess()           {}
func ShowFailure(string)     {}
func ShowAbout()             {}
func PromptPIN() ([]byte, error) {
	return nil, ErrPromptUnavailable
}
