package ageprofile

import (
	"crypto/ecdh"
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

const (
	testNativeRecipient = "age188wezz70tyq4qdjj5vyjv0cpy7j0xjhfd956vwwyqgl2f447jsyq5qsase"
	testNativeIdentity  = "AGE-SECRET-KEY-1LXG9XLV84FHVPSZFCAJRF6RJ2QDKQNSNA4LLFEQF45QNHR6UG95QSAGC6Y"
)

func TestNativeRecipientAndIdentityUseOfficialDerivation(t *testing.T) {
	publicKey, err := ParseNativeRecipient(testNativeRecipient)
	if err != nil {
		t.Fatal(err)
	}
	if got := EncodeNativeRecipient(publicKey); got != testNativeRecipient {
		t.Fatalf("recipient = %q, want %q", got, testNativeRecipient)
	}
	privateKey, err := ParseNativeIdentity(testNativeIdentity)
	if err != nil {
		t.Fatal(err)
	}
	var derivedPublicKey PublicKey
	copy(derivedPublicKey[:], privateKey.PublicKey().Bytes())
	if derivedPublicKey != publicKey {
		t.Fatal("decoded identity does not derive the official recipient public key")
	}
}

func TestNativeEncodingsRejectNonCanonicalAndLowOrderKeys(t *testing.T) {
	if _, err := ParseNativeRecipient(strings.ToUpper(testNativeRecipient)); err == nil {
		t.Fatal("uppercase native recipient was accepted")
	}
	badRecipient := testNativeRecipient[:len(testNativeRecipient)-1] + "q"
	if _, err := ParseNativeRecipient(badRecipient); err == nil {
		t.Fatal("recipient with invalid checksum was accepted")
	}
	if _, err := ParseNativeIdentity(strings.ToLower(testNativeIdentity)); err == nil {
		t.Fatal("lowercase native identity was accepted")
	}
	badIdentity := testNativeIdentity[:len(testNativeIdentity)-1] + "Q"
	_, err := ParseNativeIdentity(badIdentity)
	if err == nil {
		t.Fatal("identity with invalid checksum was accepted")
	}
	if strings.Contains(err.Error(), badIdentity) || strings.Contains(err.Error(), "SECRET-KEY") {
		t.Fatalf("identity error leaked key text: %v", err)
	}

	zeroKey, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	zeroRecipient, err := plugin.EncodeX25519Recipient(zeroKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeRecipient(zeroRecipient); err == nil {
		t.Fatal("low-order native recipient was accepted")
	}
	if got := EncodeNativeRecipient(PublicKey{}); got != "" {
		t.Fatalf("encoded invalid public key as %q", got)
	}
}
