//go:build darwin && cgo

package macos

/*
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>

void YTInitializeApplication(void);
void YTRunApplication(void);
void YTStopApplication(void);
void YTShowWaiting(const char *soundName, const char *title, const char *subtitle, const char *bundleIdentifier, int fallback, unsigned long long requestID);
void YTShowSuccess(const char *title, const char *bundleIdentifier, unsigned long long requestID);
void YTShowFailure(const char *title, const char *message, const char *bundleIdentifier, unsigned long long requestID);
void YTHide(unsigned long long requestID);
unsigned long long YTConsumeCancelRequest(void);
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

func ShowWaiting(sound string, title string, subtitle string, bundleIdentifier string, fallback bool, requestID uint64) {
	soundValue := C.CString(sound)
	defer C.free(unsafe.Pointer(soundValue))
	titleValue := C.CString(title)
	defer C.free(unsafe.Pointer(titleValue))
	subtitleValue := C.CString(subtitle)
	defer C.free(unsafe.Pointer(subtitleValue))
	bundleValue := C.CString(bundleIdentifier)
	defer C.free(unsafe.Pointer(bundleValue))
	fallbackValue := C.int(0)
	if fallback {
		fallbackValue = 1
	}
	C.YTShowWaiting(soundValue, titleValue, subtitleValue, bundleValue, fallbackValue, C.ulonglong(requestID))
}

func ShowSuccess(title string, bundleIdentifier string, requestID uint64) {
	titleValue := C.CString(title)
	defer C.free(unsafe.Pointer(titleValue))
	bundleValue := C.CString(bundleIdentifier)
	defer C.free(unsafe.Pointer(bundleValue))
	C.YTShowSuccess(titleValue, bundleValue, C.ulonglong(requestID))
}

func ShowFailure(title string, message string, bundleIdentifier string, requestID uint64) {
	titleValue := C.CString(title)
	defer C.free(unsafe.Pointer(titleValue))
	messageValue := C.CString(message)
	defer C.free(unsafe.Pointer(messageValue))
	bundleValue := C.CString(bundleIdentifier)
	defer C.free(unsafe.Pointer(bundleValue))
	C.YTShowFailure(titleValue, messageValue, bundleValue, C.ulonglong(requestID))
}

func Hide(requestID uint64) {
	C.YTHide(C.ulonglong(requestID))
}

func ConsumeCancelRequest() uint64 {
	return uint64(C.YTConsumeCancelRequest())
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
