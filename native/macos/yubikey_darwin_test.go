//go:build darwin && cgo

package macos

import "testing"

func TestYubiKeyRegistryCountAndMonitorLifecycle(t *testing.T) {
	count, err := CountYubiKeys()
	if err != nil {
		t.Fatal(err)
	}
	if count < 0 {
		t.Fatalf("YubiKey count = %d", count)
	}

	monitor, err := NewYubiKeyMonitor()
	if err != nil {
		t.Fatal(err)
	}
	if count, err := monitor.Count(); err != nil || count < 0 {
		t.Fatalf("monitor count = %d, error = %v", count, err)
	}
	events := monitor.Events()
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	for range events {
	}
}
