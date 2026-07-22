package ageprofile

import (
	"context"
	"crypto/ecdh"
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

func TestRecipientAndIdentityRoundTrip(t *testing.T) {
	_, hardware := testPrivateKey(t, 1)
	_, recovery := testPrivateKey(t, 97)
	recipient, err := NewRecipient(hardware, &recovery)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(recipient.String(), "age1yubitouch1") {
		t.Fatalf("unexpected recipient encoding %q", recipient.String())
	}
	parsedRecipient, err := ParseRecipient(recipient.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsedRecipient.String() != recipient.String() || parsedRecipient.ProfileID() != recipient.ProfileID() {
		t.Fatal("recipient did not round-trip canonically")
	}
	if parsedRecipient.Hardware() != recipient.Hardware() {
		t.Fatal("hardware key did not round-trip")
	}
	gotRecovery, ok := parsedRecipient.Recovery()
	if !ok || gotRecovery != *recipient.recovery {
		t.Fatal("recovery key did not round-trip")
	}
	if _, err := ParseRecipient(strings.ToUpper(recipient.String())); err == nil {
		t.Fatal("uppercase recipient was accepted")
	}

	identityEncoding, err := EncodeIdentity(hardware)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(identityEncoding, "AGE-PLUGIN-YUBITOUCH-1") {
		t.Fatalf("unexpected identity encoding %q", identityEncoding)
	}
	client := ClientFunc(func(context.Context, UnwrapRequest) ([]byte, error) {
		return nil, nil
	})
	identity, err := ParseIdentity(context.Background(), identityEncoding, client)
	if err != nil {
		t.Fatal(err)
	}
	if identity.String() != identityEncoding {
		t.Fatal("identity did not round-trip canonically")
	}
	if identity.ProfileID() != recipient.ProfileID() || identity.HardwareKeyID() != recipient.Hardware().ID {
		t.Fatal("identity is not bound to recipient hardware key")
	}
	if _, err := ParseIdentity(context.Background(), strings.ToLower(identityEncoding), client); err == nil {
		t.Fatal("lowercase identity was accepted")
	}
}

func TestRecipientPayloadRejectsMutations(t *testing.T) {
	_, hardware := testPrivateKey(t, 3)
	_, recovery := testPrivateKey(t, 67)
	recipient, err := NewRecipient(hardware, &recovery)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := plugin.ParseRecipient(recipient.String())
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func([]byte) []byte{
		"version":               func(p []byte) []byte { p[0]++; return p },
		"algorithm":             func(p []byte) []byte { p[1]++; return p },
		"unknown flags":         func(p []byte) []byte { p[2] |= 0x80; return p },
		"reserved":              func(p []byte) []byte { p[3] = 1; return p },
		"profile ID":            func(p []byte) []byte { p[4] ^= 1; return p },
		"hardware key ID":       func(p []byte) []byte { p[20] ^= 1; return p },
		"recovery key ID":       func(p []byte) []byte { p[68] ^= 1; return p },
		"flags without payload": func(p []byte) []byte { p[2] = 0; return p },
		"trailing byte":         func(p []byte) []byte { return append(p, 0) },
		"truncated":             func(p []byte) []byte { return p[:len(p)-1] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := append([]byte(nil), payload...)
			if _, err := ParseRecipientPayload(mutate(copy)); err == nil {
				t.Fatal("mutated payload was accepted")
			}
		})
	}

	sameKeyPayload := append([]byte(nil), payload...)
	copy(sameKeyPayload[84:116], hardware[:])
	sameRecoveryID := deriveID(recoveryKeyIDDomain, hardware)
	copy(sameKeyPayload[68:84], sameRecoveryID[:])
	if _, err := ParseRecipientPayload(sameKeyPayload); err == nil {
		t.Fatal("recipient using the same hardware and recovery key was accepted")
	}
}

func TestIdentityPayloadRejectsMutations(t *testing.T) {
	_, hardware := testPrivateKey(t, 5)
	encoding, err := EncodeIdentity(hardware)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := plugin.ParseIdentity(encoding)
	if err != nil {
		t.Fatal(err)
	}
	client := ClientFunc(func(context.Context, UnwrapRequest) ([]byte, error) { return nil, nil })

	for name, mutate := range map[string]func([]byte) []byte{
		"version":          func(p []byte) []byte { p[0]++; return p },
		"algorithm":        func(p []byte) []byte { p[1]++; return p },
		"reserved 0":       func(p []byte) []byte { p[2] = 1; return p },
		"reserved 1":       func(p []byte) []byte { p[3] = 1; return p },
		"zero profile":     func(p []byte) []byte { clear(p[4:20]); return p },
		"zero hardware ID": func(p []byte) []byte { clear(p[20:36]); return p },
		"trailing":         func(p []byte) []byte { return append(p, 0) },
		"truncated":        func(p []byte) []byte { return p[:len(p)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			copy := append([]byte(nil), payload...)
			if _, err := ParseIdentityPayload(context.Background(), mutate(copy), client); err == nil {
				t.Fatal("mutated identity was accepted")
			}
		})
	}
	if _, err := ParseIdentityPayload(context.Background(), payload, nil); err == nil {
		t.Fatal("identity without daemon client was accepted")
	}
}

func TestPublicKeyValidationRejectsNonCanonicalAndLowOrderPoints(t *testing.T) {
	var zero PublicKey
	if _, err := NewRecipient(zero, nil); err == nil {
		t.Fatal("zero public key was accepted")
	}
	var one PublicKey
	one[0] = 1
	if _, err := NewRecipient(one, nil); err == nil {
		t.Fatal("low-order public key was accepted")
	}
	_, valid := testPrivateKey(t, 13)
	highBit := valid
	highBit[31] |= 0x80
	if _, err := NewRecipient(highBit, nil); err == nil {
		t.Fatal("public key with high bit set was accepted")
	}
	var fieldPrime PublicKey
	for i := range fieldPrime {
		fieldPrime[i] = 0xff
	}
	fieldPrime[0], fieldPrime[31] = 0xed, 0x7f
	if _, err := NewRecipient(fieldPrime, nil); err == nil {
		t.Fatal("non-canonical field element was accepted")
	}
}

func testPrivateKey(t *testing.T, seed byte) (*ecdh.PrivateKey, PublicKey) {
	t.Helper()
	var scalar [32]byte
	for i := range scalar {
		scalar[i] = seed + byte(i)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	var publicKey PublicKey
	copy(publicKey[:], privateKey.PublicKey().Bytes())
	if err := validatePublicKey(publicKey); err != nil {
		t.Fatalf("test public key is invalid: %v", err)
	}
	return privateKey, publicKey
}
