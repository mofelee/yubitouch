package ageprofile

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestWrapAndUnwrapBothPaths(t *testing.T) {
	hardwarePrivate, hardwarePublic := testPrivateKey(t, 7)
	recoveryPrivate, recoveryPublic := testPrivateKey(t, 79)
	recipient, err := NewRecipient(hardwarePublic, &recoveryPublic)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars())
	fileKey := []byte("0123456789abcdef")
	stanzas, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(stanzas) != 2 {
		t.Fatalf("got %d stanzas, want 2", len(stanzas))
	}

	hardwareEnvelope, err := ParseEnvelope(stanzas[0])
	if err != nil {
		t.Fatal(err)
	}
	recoveryEnvelope, err := ParseEnvelope(stanzas[1])
	if err != nil {
		t.Fatal(err)
	}
	if hardwareEnvelope.Path != PathHardware || recoveryEnvelope.Path != PathRecovery {
		t.Fatalf("unexpected paths %v and %v", hardwareEnvelope.Path, recoveryEnvelope.Path)
	}
	if hardwareEnvelope.ProfileID != recoveryEnvelope.ProfileID || hardwareEnvelope.ProfileID != recipient.ProfileID() {
		t.Fatal("stanzas are not bound to the same profile")
	}
	if hardwareEnvelope.EphemeralPublicKey == recoveryEnvelope.EphemeralPublicKey {
		t.Fatal("wrapping paths reused an ephemeral key")
	}

	gotHardware, err := UnwrapWithPrivateKey(hardwareEnvelope, hardwarePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHardware, fileKey) {
		t.Fatalf("hardware file key = %x, want %x", gotHardware, fileKey)
	}
	gotRecovery, err := UnwrapWithPrivateKey(recoveryEnvelope, recoveryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRecovery, fileKey) {
		t.Fatalf("recovery file key = %x, want %x", gotRecovery, fileKey)
	}

	ephemeral, err := ecdh.X25519().NewPublicKey(hardwareEnvelope.EphemeralPublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err := hardwarePrivate.ECDH(ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	gotExternal, err := UnwrapWithSharedSecret(hardwareEnvelope, hardwarePublic, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotExternal, fileKey) {
		t.Fatalf("external ECDH file key = %x, want %x", gotExternal, fileKey)
	}
}

func TestProtocolGoldenVector(t *testing.T) {
	_, hardware := testPrivateKey(t, 7)
	_, recovery := testPrivateKey(t, 79)
	recipient, err := NewRecipient(hardware, &recovery)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := EncodeIdentity(hardware)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars())
	stanzas, err := recipient.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	const wantRecipient = "age1yubitouch1qyqszqznu762qg6exkgkf35sfagknsavfzlfeqf433uqwur6ur4njc5xgvrm332zfpmgdfurqxz4ljmd8a4g4ygu6lcesw5mgnwfmnfzswwj8sklzu6rz9y4wr506ksj5sz7k88gxt9pm0n8hy0cv6sdvxpkvem4vfru8mctlkznyws572dnpep8zcltz7v9"
	const wantIdentity = "AGE-PLUGIN-YUBITOUCH-1QYQSQQZNU762QG6EXKGKF35SFAGKNSAVFZLFEQF433UQWUR6UR4NJC5XGVXF2GCH"
	const wantHardwareArgs = "v1 hardware 53e7b4a02359359164c6904f5169c3ac 48be9c81358c7807707ae0eb39628643"
	const wantHardwareBody = "d9d98527749513a99bad389e19e71f3819ecd2cba1782743f4a71d602f1f05353e65d289bd0874992e5c376f64e98f9acae965d4de6bbfd8d8a62e1b05f60406"
	const wantRecoveryArgs = "v1 recovery 53e7b4a02359359164c6904f5169c3ac c2df173431149570e8fd5a12a405eb1c"
	const wantRecoveryBody = "fce51e3e2fa5a17e21c581d8b1d68476d730b350e99a63c2da3505ab3ff84031521c4b901e286dd2eb22234356596af73f090ea33f92e4d0412b1894a80179a8"

	if recipient.String() != wantRecipient || identity != wantIdentity {
		t.Fatal("recipient or identity encoding changed")
	}
	if strings.Join(stanzas[0].Args, " ") != wantHardwareArgs || hex.EncodeToString(stanzas[0].Body) != wantHardwareBody {
		t.Fatal("hardware stanza vector changed")
	}
	if strings.Join(stanzas[1].Args, " ") != wantRecoveryArgs || hex.EncodeToString(stanzas[1].Body) != wantRecoveryBody {
		t.Fatal("recovery stanza vector changed")
	}
}

func TestWrapWithoutRecoveryAndFileKeySize(t *testing.T) {
	_, hardware := testPrivateKey(t, 11)
	recipient, err := NewRecipient(hardware, nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars()[:32])
	stanzas, err := recipient.Wrap(make([]byte, fileKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if len(stanzas) != 1 {
		t.Fatalf("got %d stanzas, want 1", len(stanzas))
	}
	if _, err := recipient.Wrap(make([]byte, fileKeySize-1)); err == nil {
		t.Fatal("short file key was accepted")
	}
	if _, err := recipient.Wrap(make([]byte, fileKeySize+1)); err == nil {
		t.Fatal("long file key was accepted")
	}
}

func TestUnwrapRejectsTamperingAndInvalidInputs(t *testing.T) {
	privateKey, publicKey := testPrivateKey(t, 17)
	recipient, err := NewRecipient(publicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars()[:32])
	stanzas, err := recipient.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ParseEnvelope(stanzas[0])
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(envelope.EphemeralPublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err := privateKey.ECDH(ephemeral)
	if err != nil {
		t.Fatal(err)
	}

	tamperedCiphertext := envelope
	tamperedCiphertext.Ciphertext[0] ^= 1
	if _, err := UnwrapWithSharedSecret(tamperedCiphertext, publicKey, sharedSecret); err == nil {
		t.Fatal("tampered ciphertext authenticated")
	}
	tamperedProfile := envelope
	tamperedProfile.ProfileID[0] ^= 1
	if _, err := UnwrapWithSharedSecret(tamperedProfile, publicKey, sharedSecret); err == nil {
		t.Fatal("tampered profile ID authenticated")
	}
	tamperedPath := envelope
	tamperedPath.Path = PathRecovery
	if _, err := UnwrapWithSharedSecret(tamperedPath, publicKey, sharedSecret); err == nil {
		t.Fatal("tampered path authenticated")
	}
	_, wrongPublicKey := testPrivateKey(t, 117)
	if _, err := UnwrapWithSharedSecret(envelope, wrongPublicKey, sharedSecret); err == nil {
		t.Fatal("wrong recipient public key was accepted")
	}
	if _, err := UnwrapWithSharedSecret(envelope, publicKey, sharedSecret[:31]); err == nil {
		t.Fatal("short shared secret was accepted")
	}
	if _, err := UnwrapWithSharedSecret(envelope, publicKey, make([]byte, 32)); err == nil {
		t.Fatal("zero shared secret was accepted")
	}
	if _, err := UnwrapWithPrivateKey(envelope, nil); err == nil {
		t.Fatal("nil private key was accepted")
	}
	p256Private, err := ecdh.P256().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapWithPrivateKey(envelope, p256Private); err == nil {
		t.Fatal("P-256 private key was accepted")
	}
}

func TestEnvelopeParsingIsStrict(t *testing.T) {
	_, hardware := testPrivateKey(t, 23)
	recipient, err := NewRecipient(hardware, nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars()[:32])
	stanzas, err := recipient.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	valid := stanzas[0]

	tests := map[string]func(*age.Stanza){
		"wrong type":          func(s *age.Stanza) { s.Type = "X25519" },
		"missing arg":         func(s *age.Stanza) { s.Args = s.Args[:3] },
		"extra arg":           func(s *age.Stanza) { s.Args = append(s.Args, "extra") },
		"version":             func(s *age.Stanza) { s.Args[0] = "v2" },
		"path":                func(s *age.Stanza) { s.Args[1] = "other" },
		"uppercase profile":   func(s *age.Stanza) { s.Args[2] = strings.ToUpper(s.Args[2]) },
		"short profile":       func(s *age.Stanza) { s.Args[2] = s.Args[2][:31] },
		"zero profile":        func(s *age.Stanza) { s.Args[2] = strings.Repeat("0", 32) },
		"uppercase key":       func(s *age.Stanza) { s.Args[3] = strings.ToUpper(s.Args[3]) },
		"zero key":            func(s *age.Stanza) { s.Args[3] = strings.Repeat("0", 32) },
		"short body":          func(s *age.Stanza) { s.Body = s.Body[:len(s.Body)-1] },
		"long body":           func(s *age.Stanza) { s.Body = append(s.Body, 0) },
		"low-order ephemeral": func(s *age.Stanza) { clear(s.Body[:32]) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := cloneStanza(valid)
			mutate(copy)
			if _, err := ParseEnvelope(copy); err == nil {
				t.Fatal("invalid stanza was accepted")
			}
		})
	}
	if _, err := ParseEnvelope(nil); err == nil {
		t.Fatal("nil stanza was accepted")
	}
}

func TestWrapPropagatesRandomSourceFailure(t *testing.T) {
	_, hardware := testPrivateKey(t, 29)
	recipient, err := NewRecipient(hardware, nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = errorReader{}
	if _, err := recipient.Wrap(make([]byte, fileKeySize)); err == nil {
		t.Fatal("random source failure was ignored")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("test random failure")
}

func cloneStanza(stanza *age.Stanza) *age.Stanza {
	return &age.Stanza{
		Type: stanza.Type,
		Args: append([]string(nil), stanza.Args...),
		Body: append([]byte(nil), stanza.Body...),
	}
}

func testEphemeralScalars() []byte {
	scalars := make([]byte, 64)
	for i := range scalars {
		scalars[i] = byte(i + 31)
	}
	return scalars
}
