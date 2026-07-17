//go:build darwin && cgo

package macos

/*
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>

void YTInitializeApplication(void);
void YTRunApplication(void);
void YTStopApplication(void);
void YTShowWaiting(const char *soundName);
void YTShowSuccess(void);
void YTShowFailure(const char *message);
void YTShowAbout(void);
char *YTPromptPIN(int *status);
*/
import "C"

import (
	"errors"
	"unsafe"
)

var ErrPromptUnavailable = errors.New("native PIN prompt is unavailable")
var ErrPromptCanceled = errors.New("PIN prompt was canceled")

func InitializeApplication() {
	C.YTInitializeApplication()
}

func RunApplication() {
	C.YTRunApplication()
}

func StopApplication() {
	C.YTStopApplication()
}

func ShowWaiting(sound string) {
	value := C.CString(sound)
	defer C.free(unsafe.Pointer(value))
	C.YTShowWaiting(value)
}

func ShowSuccess() {
	C.YTShowSuccess()
}

func ShowFailure(message string) {
	value := C.CString(message)
	defer C.free(unsafe.Pointer(value))
	C.YTShowFailure(value)
}

func ShowAbout() {
	C.YTShowAbout()
}

func PromptPIN() ([]byte, error) {
	var status C.int
	value := C.YTPromptPIN(&status)
	if value != nil {
		defer C.free(unsafe.Pointer(value))
	}
	switch status {
	case 0:
		if value == nil {
			return nil, ErrPromptUnavailable
		}
		return []byte(C.GoString(value)), nil
	case 1:
		return nil, ErrPromptCanceled
	default:
		return nil, ErrPromptUnavailable
	}
}
