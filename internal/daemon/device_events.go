package daemon

import (
	"context"
	"errors"
	"sync"

	"github.com/mofelee/yubitouch/internal/config"
)

// deviceEventStreams gives each daemon subsystem its own coalescing event
// stream. A slow consumer must not prevent another consumer from invalidating
// state after a device change.
type deviceEventStreams struct {
	Router <-chan struct{}
	Age    <-chan struct{}
}

func needsYubiKeyMonitor(cfg config.Config) bool {
	return cfg.Age != nil || cfg.FallbackAgent == config.FallbackAgent1Password
}

func fanOutDeviceEvents(source <-chan struct{}) deviceEventStreams {
	if source == nil {
		return deviceEventStreams{}
	}
	router := make(chan struct{}, 1)
	age := make(chan struct{}, 1)
	go func() {
		defer close(router)
		defer close(age)
		for range source {
			publishDeviceEvent(router)
			publishDeviceEvent(age)
		}
	}()
	return deviceEventStreams{Router: router, Age: age}
}

func publishDeviceEvent(destination chan<- struct{}) {
	select {
	case destination <- struct{}{}:
	default:
	}
}

type ageHardwareSessions interface {
	Invalidate() error
	Close() error
}

func ageHardwareInvalidator(sessions ageHardwareSessions) func() error {
	if sessions == nil {
		return nil
	}
	return sessions.Invalidate
}

// ageHardwareSessionWatcher owns the manager's lifetime. Every device change
// invalidates retained PKCS#11 state; source closure and daemon shutdown close
// and reap the persistent helper.
type ageHardwareSessionWatcher struct {
	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
	err      error
}

func startAgeHardwareSessionWatcher(
	events <-chan struct{},
	sessions ageHardwareSessions,
) *ageHardwareSessionWatcher {
	if sessions == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &ageHardwareSessionWatcher{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(watcher.done)
		defer func() { watcher.err = errors.Join(watcher.err, sessions.Close()) }()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-events:
				if !ok {
					return
				}
				if err := sessions.Invalidate(); err != nil {
					watcher.err = err
					return
				}
			}
		}
	}()
	return watcher
}

func (w *ageHardwareSessionWatcher) stop() error {
	if w == nil {
		return nil
	}
	w.stopOnce.Do(w.cancel)
	<-w.done
	return w.err
}
