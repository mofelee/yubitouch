package ageprofile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"filippo.io/age"
)

func TestIdentitySelectsAndDelegatesValidatedProfile(t *testing.T) {
	_, hardware := testPrivateKey(t, 31)
	_, recovery := testPrivateKey(t, 89)
	recipient, err := NewRecipient(hardware, &recovery)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars())
	fileKey := []byte("0123456789abcdef")
	stanzas, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "request-context")
	var gotRequest UnwrapRequest
	clientCalls := 0
	client := ClientFunc(func(gotContext context.Context, request UnwrapRequest) ([]byte, error) {
		clientCalls++
		if gotContext.Value(contextKey{}) != "request-context" {
			t.Fatal("identity did not propagate its context")
		}
		gotRequest = request
		return append([]byte(nil), fileKey...), nil
	})
	identity, err := NewIdentity(ctx, hardware, client)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]*age.Stanza{{Type: "X25519", Args: []string{"ignored"}}}, stanzas...)
	gotFileKey, err := identity.Unwrap(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotFileKey, fileKey) {
		t.Fatalf("file key = %x, want %x", gotFileKey, fileKey)
	}
	if clientCalls != 1 {
		t.Fatalf("client calls = %d, want 1", clientCalls)
	}
	if gotRequest.ProfileID != recipient.ProfileID() || gotRequest.HardwareKeyID != recipient.Hardware().ID {
		t.Fatal("request identifiers do not match recipient")
	}
	if gotRequest.Hardware.Path != PathHardware || gotRequest.Recovery == nil || gotRequest.Recovery.Path != PathRecovery {
		t.Fatal("request did not include both validated paths")
	}
}

func TestAgeLibraryRoundTripThroughHardwareAndRecoveryClients(t *testing.T) {
	hardwarePrivate, hardware := testPrivateKey(t, 33)
	recoveryPrivate, recovery := testPrivateKey(t, 91)
	recipient, err := NewRecipient(hardware, &recovery)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("YubiTouch age profile integration test")
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	for name, client := range map[string]Client{
		"hardware": ClientFunc(func(_ context.Context, request UnwrapRequest) ([]byte, error) {
			return UnwrapWithPrivateKey(request.Hardware, hardwarePrivate)
		}),
		"recovery": ClientFunc(func(_ context.Context, request UnwrapRequest) ([]byte, error) {
			if request.Recovery == nil {
				return nil, errors.New("missing recovery envelope")
			}
			return UnwrapWithPrivateKey(*request.Recovery, recoveryPrivate)
		}),
	} {
		t.Run(name, func(t *testing.T) {
			identity, err := NewIdentity(context.Background(), hardware, client)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := age.Decrypt(bytes.NewReader(encrypted.Bytes()), identity)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("plaintext = %q, want %q", got, plaintext)
			}
		})
	}
}

func TestIdentityReturnsIncorrectIdentityWithoutDaemonSideEffects(t *testing.T) {
	_, hardware := testPrivateKey(t, 37)
	_, otherHardware := testPrivateKey(t, 101)
	otherRecipient, err := NewRecipient(otherHardware, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherRecipient.rand = bytes.NewReader(testEphemeralScalars()[:32])
	otherStanzas, err := otherRecipient.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	identity, err := NewIdentity(context.Background(), hardware, ClientFunc(func(context.Context, UnwrapRequest) ([]byte, error) {
		calls++
		return nil, errors.New("must not be called")
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = identity.Unwrap(append([]*age.Stanza{{Type: "X25519"}}, otherStanzas...))
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("error = %v, want ErrIncorrectIdentity", err)
	}
	if calls != 0 {
		t.Fatalf("daemon client called %d times for an unrelated profile", calls)
	}
}

func TestIdentityRejectsMalformedSetsBeforeDaemonCall(t *testing.T) {
	_, hardware := testPrivateKey(t, 41)
	_, recovery := testPrivateKey(t, 109)
	recipient, err := NewRecipient(hardware, &recovery)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars())
	stanzas, err := recipient.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func() []*age.Stanza{
		"duplicate hardware": func() []*age.Stanza {
			return []*age.Stanza{cloneStanza(stanzas[0]), cloneStanza(stanzas[0])}
		},
		"duplicate recovery": func() []*age.Stanza {
			return []*age.Stanza{cloneStanza(stanzas[0]), cloneStanza(stanzas[1]), cloneStanza(stanzas[1])}
		},
		"missing hardware": func() []*age.Stanza {
			return []*age.Stanza{cloneStanza(stanzas[1])}
		},
		"wrong hardware key ID": func() []*age.Stanza {
			copy := cloneStanza(stanzas[0])
			copy.Args[3] = deriveID(hardwareKeyIDDomain, recovery).String()
			return []*age.Stanza{copy}
		},
		"recovery reuses hardware ID": func() []*age.Stanza {
			recoveryCopy := cloneStanza(stanzas[1])
			recoveryCopy.Args[3] = recipient.Hardware().ID.String()
			return []*age.Stanza{cloneStanza(stanzas[0]), recoveryCopy}
		},
		"malformed matching stanza": func() []*age.Stanza {
			copy := cloneStanza(stanzas[0])
			copy.Args[0] = "v2"
			return []*age.Stanza{copy}
		},
		"nil stanza": func() []*age.Stanza {
			return []*age.Stanza{nil}
		},
	}
	for name, makeStanzas := range tests {
		t.Run(name, func(t *testing.T) {
			calls := 0
			identity, err := NewIdentity(context.Background(), hardware, ClientFunc(func(context.Context, UnwrapRequest) ([]byte, error) {
				calls++
				return nil, errors.New("must not be called")
			}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identity.Unwrap(makeStanzas()); err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
				t.Fatalf("error = %v, want fatal validation error", err)
			}
			if calls != 0 {
				t.Fatalf("daemon client called %d times", calls)
			}
		})
	}
}

func TestIdentityTreatsMatchingDaemonFailuresAsFatal(t *testing.T) {
	_, hardware := testPrivateKey(t, 47)
	recipient, err := NewRecipient(hardware, nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient.rand = bytes.NewReader(testEphemeralScalars()[:32])
	stanzas, err := recipient.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	identity, err := NewIdentity(context.Background(), hardware, ClientFunc(func(context.Context, UnwrapRequest) ([]byte, error) {
		return nil, age.ErrIncorrectIdentity
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Unwrap(stanzas); err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("matching daemon error = %v, want fatal error", err)
	}

	identity, err = NewIdentity(context.Background(), hardware, ClientFunc(func(context.Context, UnwrapRequest) ([]byte, error) {
		return make([]byte, fileKeySize-1), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Unwrap(stanzas); err == nil {
		t.Fatal("short daemon file key was accepted")
	}
}
