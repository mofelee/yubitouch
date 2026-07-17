package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseHardwareOutputs(t *testing.T) {
	fields := parseMetadata([]byte("Key slot: 9A (AUTHENTICATION)\nAlgorithm: ED25519\nPIN required for use: ONCE\nTouch required for use: ALWAYS\n"))
	if fields["Algorithm"] != "ED25519" || fields["Touch required for use"] != "ALWAYS" {
		t.Fatalf("fields = %v", fields)
	}
	if got := countNonEmptyLines([]byte("123\n\n456\n")); got != 2 {
		t.Fatalf("device count = %d", got)
	}
}

func TestProbeYubiKeysCountsDevicesWithoutReturningSerials(t *testing.T) {
	lookup := func(name string) (string, error) {
		if name != "ykman" {
			t.Fatalf("lookup = %q", name)
		}
		return "/test/ykman", nil
	}
	run := func(_ context.Context, path string, args ...string) ([]byte, []byte, error) {
		if path != "/test/ykman" || len(args) != 2 || args[0] != "list" || args[1] != "--serials" {
			t.Fatalf("command = %s %v", path, args)
		}
		return []byte("12345678\n87654321\n"), nil, nil
	}
	count, err := probeYubiKeys(context.Background(), lookup, run)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("device count = %d, want 2", count)
	}
}

func TestProbeYubiKeysClassifiesUnavailableToolAndProbeFailure(t *testing.T) {
	_, err := probeYubiKeys(context.Background(), func(string) (string, error) {
		return "", errors.New("missing")
	}, nil)
	if !errors.Is(err, ErrYKManUnavailable) {
		t.Fatalf("missing tool error = %v", err)
	}

	_, err = probeYubiKeys(context.Background(), func(string) (string, error) {
		return "/test/ykman", nil
	}, func(context.Context, string, ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("timed out")
	})
	if !errors.Is(err, ErrDeviceProbe) {
		t.Fatalf("probe error = %v", err)
	}

	_, err = probeYubiKeys(context.Background(), func(string) (string, error) {
		return "/test/ykman", nil
	}, func(context.Context, string, ...string) ([]byte, []byte, error) {
		return nil, []byte("PC/SC access denied"), nil
	})
	if !errors.Is(err, ErrDeviceProbe) {
		t.Fatalf("stderr-only probe error = %v", err)
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
