package daemon

import "github.com/mofelee/yubitouch/internal/config"

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
