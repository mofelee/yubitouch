package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/mofelee/yubitouch/internal/config"
	"golang.org/x/crypto/ssh"
)

func TestParseHardwareOutputs(t *testing.T) {
	fields := parseMetadata([]byte("Key slot: 9A (AUTHENTICATION)\nAlgorithm: ED25519\nPIN required for use: ONCE\nTouch required for use: ALWAYS\n"))
	if fields["Algorithm"] != "ED25519" || fields["Touch required for use"] != "ALWAYS" {
		t.Fatalf("fields = %v", fields)
	}
}

func TestProbeYubiKeysUsesNonInteractiveDeviceCounter(t *testing.T) {
	calls := 0
	count, err := probeYubiKeys(context.Background(), func() (int, error) {
		calls++
		return 2, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || calls != 1 {
		t.Fatalf("device count = %d calls = %d, want 2 and 1", count, calls)
	}
}

func TestProbeYubiKeysClassifiesCounterFailureAndCancellation(t *testing.T) {
	_, err := probeYubiKeys(context.Background(), func() (int, error) {
		return 0, errors.New("IOKit unavailable")
	})
	if !errors.Is(err, ErrDeviceProbe) {
		t.Fatalf("probe error = %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err = probeYubiKeys(canceled, func() (int, error) {
		called = true
		return 0, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe error = %v", err)
	}
	if called {
		t.Fatal("device counter ran after context cancellation")
	}
}

func TestInspectHardwareClassifiesMissingDevice(t *testing.T) {
	report, err := inspectHardware(context.Background(), config.Config{}, Dependencies{}, func(context.Context) (int, error) {
		return 0, nil
	})
	if !errors.Is(err, ErrDeviceNotDetected) || report.DeviceCount != 0 {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

func TestInspectProviderKeys(t *testing.T) {
	target := newTestPublicKey(t)
	other := newTestPublicKey(t)
	output := append(ssh.MarshalAuthorizedKey(target), ssh.MarshalAuthorizedKey(other)...)
	found, otherCount := inspectProviderKeys(output, target)
	if !found || otherCount != 1 {
		t.Fatalf("found=%v other=%d", found, otherCount)
	}
}

func newTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
