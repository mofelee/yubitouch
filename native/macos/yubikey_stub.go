//go:build !darwin || !cgo

package macos

import "errors"

var ErrYubiKeyMonitorUnavailable = errors.New("native YubiKey monitor is unavailable")

type YubiKeyMonitor struct{}

func CountYubiKeys() (int, error) {
	return 0, ErrYubiKeyMonitorUnavailable
}

func NewYubiKeyMonitor() (*YubiKeyMonitor, error) {
	return nil, ErrYubiKeyMonitorUnavailable
}

func (*YubiKeyMonitor) Count() (int, error) {
	return 0, ErrYubiKeyMonitorUnavailable
}

func (*YubiKeyMonitor) Events() <-chan struct{} {
	return nil
}

func (*YubiKeyMonitor) Close() error {
	return nil
}
