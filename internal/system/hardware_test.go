package system

import (
	"crypto/ed25519"
	"crypto/rand"
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
