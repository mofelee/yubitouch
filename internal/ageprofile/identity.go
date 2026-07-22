package ageprofile

import (
	"context"
	"errors"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// UnwrapRequest contains the fully validated envelopes for one local profile.
// The daemon client must still bind these identifiers to its configured and
// actual public keys before performing a private-key operation.
type UnwrapRequest struct {
	ProfileID     ID
	HardwareKeyID ID
	Hardware      Envelope
	Recovery      *Envelope
}

// Client delegates private-key selection and unwrapping to the YubiTouch
// daemon. Implementations must return exactly one 16-byte age file key.
type Client interface {
	Unwrap(context.Context, UnwrapRequest) ([]byte, error)
}

// ClientFunc adapts a function into a Client.
type ClientFunc func(context.Context, UnwrapRequest) ([]byte, error)

func (f ClientFunc) Unwrap(ctx context.Context, request UnwrapRequest) ([]byte, error) {
	if f == nil {
		return nil, errors.New("age daemon client is unavailable")
	}
	return f(ctx, request)
}

// Identity is a local profile descriptor backed by a daemon Client.
type Identity struct {
	ctx           context.Context
	client        Client
	profileID     ID
	hardwareKeyID ID
}

var _ age.Identity = (*Identity)(nil)

// NewIdentity constructs an identity bound to a hardware public key.
func NewIdentity(ctx context.Context, hardware PublicKey, client Client) (*Identity, error) {
	if err := validatePublicKey(hardware); err != nil {
		return nil, fmt.Errorf("invalid hardware public key: %w", err)
	}
	if client == nil {
		return nil, errors.New("age daemon client is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &Identity{
		ctx:           ctx,
		client:        client,
		profileID:     deriveID(profileIDDomain, hardware),
		hardwareKeyID: deriveID(hardwareKeyIDDomain, hardware),
	}, nil
}

// EncodeIdentity encodes a stable descriptor for a hardware public key.
func EncodeIdentity(hardware PublicKey) (string, error) {
	if err := validatePublicKey(hardware); err != nil {
		return "", fmt.Errorf("invalid hardware public key: %w", err)
	}
	payload := encodeIdentityPayload(
		deriveID(profileIDDomain, hardware),
		deriveID(hardwareKeyIDDomain, hardware),
	)
	return plugin.EncodeIdentity(PluginName, payload), nil
}

// ParseIdentity parses a canonical AGE-PLUGIN-YUBITOUCH-1... descriptor.
func ParseIdentity(ctx context.Context, s string, client Client) (*Identity, error) {
	name, payload, err := plugin.ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	if name != PluginName {
		return nil, fmt.Errorf("unsupported plugin name %q", name)
	}
	identity, err := ParseIdentityPayload(ctx, payload, client)
	if err != nil {
		return nil, err
	}
	if identity.String() != s {
		return nil, errors.New("identity encoding is not canonical")
	}
	return identity, nil
}

// ParseIdentityPayload parses the decoded payload passed by the age plugin
// framework. The daemon Client is responsible for recomputing the identifiers
// from its configured hardware public key.
func ParseIdentityPayload(ctx context.Context, payload []byte, client Client) (*Identity, error) {
	if len(payload) != identityPayloadSize {
		return nil, fmt.Errorf("invalid identity payload size %d", len(payload))
	}
	if payload[0] != ProtocolVersion {
		return nil, fmt.Errorf("unsupported identity version %d", payload[0])
	}
	if payload[1] != AlgorithmX25519 {
		return nil, fmt.Errorf("unsupported identity algorithm %d", payload[1])
	}
	if payload[2] != 0 || payload[3] != 0 {
		return nil, errors.New("identity reserved bytes are non-zero")
	}
	if client == nil {
		return nil, errors.New("age daemon client is required")
	}
	var profileID, hardwareKeyID ID
	copy(profileID[:], payload[4:20])
	copy(hardwareKeyID[:], payload[20:36])
	if profileID.isZero() {
		return nil, errors.New("identity profile ID is zero")
	}
	if hardwareKeyID.isZero() {
		return nil, errors.New("identity hardware key ID is zero")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &Identity{
		ctx:           ctx,
		client:        client,
		profileID:     profileID,
		hardwareKeyID: hardwareKeyID,
	}, nil
}

// String returns the canonical age plugin identity encoding.
func (i *Identity) String() string {
	return plugin.EncodeIdentity(PluginName, encodeIdentityPayload(i.profileID, i.hardwareKeyID))
}

// ProfileID returns the stable local profile identifier.
func (i *Identity) ProfileID() ID {
	return i.profileID
}

// HardwareKeyID returns the configured hardware key identifier.
func (i *Identity) HardwareKeyID() ID {
	return i.hardwareKeyID
}

// Unwrap validates the full matching stanza set before invoking the daemon.
func (i *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	request, err := i.selectRequest(stanzas)
	if err != nil {
		return nil, err
	}
	fileKey, err := i.client.Unwrap(i.ctx, request)
	if err != nil {
		if errors.Is(err, age.ErrIncorrectIdentity) {
			return nil, errors.New("YubiTouch daemon rejected a matching profile")
		}
		return nil, fmt.Errorf("YubiTouch daemon could not unwrap file key: %w", err)
	}
	if len(fileKey) != fileKeySize {
		clear(fileKey)
		return nil, fmt.Errorf("YubiTouch daemon returned a %d-byte file key, want %d", len(fileKey), fileKeySize)
	}
	return fileKey, nil
}

func (i *Identity) selectRequest(stanzas []*age.Stanza) (UnwrapRequest, error) {
	request := UnwrapRequest{
		ProfileID:     i.profileID,
		HardwareKeyID: i.hardwareKeyID,
	}
	var hardwareFound, recoveryFound bool
	for _, stanza := range stanzas {
		if stanza == nil {
			return UnwrapRequest{}, errors.New("age header contains a nil recipient stanza")
		}
		if stanza.Type != StanzaType {
			continue
		}
		envelope, err := ParseEnvelope(stanza)
		if err != nil {
			return UnwrapRequest{}, fmt.Errorf("invalid yubitouch stanza: %w", err)
		}
		if envelope.ProfileID != i.profileID {
			continue
		}
		switch envelope.Path {
		case PathHardware:
			if hardwareFound {
				return UnwrapRequest{}, errors.New("duplicate hardware stanza for YubiTouch profile")
			}
			if envelope.KeyID != i.hardwareKeyID {
				return UnwrapRequest{}, errors.New("hardware stanza key ID does not match YubiTouch identity")
			}
			request.Hardware = envelope
			hardwareFound = true
		case PathRecovery:
			if recoveryFound {
				return UnwrapRequest{}, errors.New("duplicate recovery stanza for YubiTouch profile")
			}
			if envelope.KeyID == i.hardwareKeyID {
				return UnwrapRequest{}, errors.New("recovery stanza reuses the hardware key ID")
			}
			copy := envelope
			request.Recovery = &copy
			recoveryFound = true
		default:
			return UnwrapRequest{}, fmt.Errorf("unknown yubitouch path %d", envelope.Path)
		}
	}
	if !hardwareFound && !recoveryFound {
		return UnwrapRequest{}, fmt.Errorf("YubiTouch profile did not match any recipient stanza: %w", age.ErrIncorrectIdentity)
	}
	if !hardwareFound {
		return UnwrapRequest{}, errors.New("YubiTouch profile is missing its hardware stanza")
	}
	return request, nil
}

func encodeIdentityPayload(profileID, hardwareKeyID ID) []byte {
	payload := make([]byte, identityPayloadSize)
	payload[0] = ProtocolVersion
	payload[1] = AlgorithmX25519
	copy(payload[4:20], profileID[:])
	copy(payload[20:36], hardwareKeyID[:])
	return payload
}
