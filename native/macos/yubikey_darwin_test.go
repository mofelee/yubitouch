//go:build darwin && cgo

package macos

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestConnectedYubicoDeviceIsCounted(t *testing.T) {
	output, err := exec.Command(
		"/usr/sbin/ioreg",
		"-r",
		"-c", "IOUSBHostDevice",
		"-d", "0",
		"-l",
	).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte(`"idVendor" = 4176`)) {
		t.Skip("no Yubico USB device is connected")
	}
	count, err := CountYubiKeys()
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("IOKit did not count the connected Yubico USB device")
	}
}

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
