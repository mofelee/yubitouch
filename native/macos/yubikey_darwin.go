//go:build darwin && cgo

package macos

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation

typedef struct YTYubiKeyMonitor YTYubiKeyMonitor;

int YTCountYubiKeys(int *count);
YTYubiKeyMonitor *YTCreateYubiKeyMonitor(int *readFD, int *count, int *status);
int YTYubiKeyMonitorSnapshot(YTYubiKeyMonitor *monitor, int *count);
void YTDestroyYubiKeyMonitor(YTYubiKeyMonitor *monitor);
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

var ErrYubiKeyMonitorUnavailable = errors.New("native YubiKey monitor is unavailable")

type YubiKeyMonitor struct {
	mu       sync.RWMutex
	handle   *C.YTYubiKeyMonitor
	reader   *os.File
	events   chan struct{}
	done     chan struct{}
	close    sync.Once
	closeErr error
}

func CountYubiKeys() (int, error) {
	var count C.int
	if status := C.YTCountYubiKeys(&count); status != 0 {
		return 0, monitorError(status)
	}
	return int(count), nil
}

func NewYubiKeyMonitor() (*YubiKeyMonitor, error) {
	var readFD, count, status C.int
	handle := C.YTCreateYubiKeyMonitor(&readFD, &count, &status)
	if handle == nil {
		return nil, monitorError(status)
	}
	reader := os.NewFile(uintptr(readFD), "yubitouch-yubikey-events")
	if reader == nil {
		C.YTDestroyYubiKeyMonitor(handle)
		return nil, ErrYubiKeyMonitorUnavailable
	}
	monitor := &YubiKeyMonitor{
		handle: handle,
		reader: reader,
		events: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	go monitor.readEvents()
	return monitor, nil
}

func (m *YubiKeyMonitor) Count() (int, error) {
	if m == nil {
		return 0, ErrYubiKeyMonitorUnavailable
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return 0, ErrYubiKeyMonitorUnavailable
	}
	var count C.int
	if status := C.YTYubiKeyMonitorSnapshot(m.handle, &count); status != 0 {
		return 0, monitorError(status)
	}
	return int(count), nil
}

func (m *YubiKeyMonitor) Events() <-chan struct{} {
	if m == nil {
		return nil
	}
	return m.events
}

func (m *YubiKeyMonitor) Close() error {
	if m == nil {
		return nil
	}
	m.close.Do(func() {
		m.mu.Lock()
		handle := m.handle
		m.handle = nil
		if handle != nil {
			C.YTDestroyYubiKeyMonitor(handle)
		}
		m.mu.Unlock()
		<-m.done
	})
	return m.closeErr
}

func (m *YubiKeyMonitor) readEvents() {
	defer close(m.done)
	defer close(m.events)
	defer func() {
		if err := m.reader.Close(); err != nil {
			m.closeErr = err
		}
	}()
	buffer := make([]byte, 64)
	for {
		count, err := m.reader.Read(buffer)
		if count > 0 {
			select {
			case m.events <- struct{}{}:
			default:
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				m.closeErr = err
			}
			return
		}
	}
}

func monitorError(status C.int) error {
	return fmt.Errorf("%w (status %#x)", ErrYubiKeyMonitorUnavailable, uint32(status))
}
