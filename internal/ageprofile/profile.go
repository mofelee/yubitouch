package ageprofile

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"fmt"

	"filippo.io/age/plugin"
)

const (
	PluginName = "yubitouch"
	StanzaType = "yubitouch"

	ProtocolVersion byte = 1
	AlgorithmX25519 byte = 1

	recipientHeaderSize  = 4
	identityPayloadSize  = 4 + 16 + 16
	recipientPayloadSize = recipientHeaderSize + 16 + 16 + 32
	recoveryPayloadSize  = 16 + 32
	recoveryFlag         = 1 << 0
)

const (
	hardwareKeyIDDomain = "age-plugin-yubitouch/v1/hardware-key-id"
	recoveryKeyIDDomain = "age-plugin-yubitouch/v1/recovery-key-id"
	profileIDDomain     = "age-plugin-yubitouch/v1/profile-id"
)

// ID is a protocol identifier encoded as 16 lowercase hexadecimal bytes in
// recipient stanzas.
type ID [16]byte

func (id ID) String() string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(id)*2)
	for i, b := range id {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

func (id ID) isZero() bool {
	return id == ID{}
}

// PublicKey is a canonical X25519 public key.
type PublicKey [32]byte

// Key identifies one wrapping path and its public key.
type Key struct {
	ID        ID
	PublicKey PublicKey
}

// Recipient is the public, device-independent form of one YubiTouch profile.
type Recipient struct {
	profileID ID
	hardware  Key
	recovery  *Key
	rand      randomReader
}

// NewRecipient constructs a recipient from canonical X25519 public keys.
func NewRecipient(hardware PublicKey, recovery *PublicKey) (*Recipient, error) {
	if err := validatePublicKey(hardware); err != nil {
		return nil, fmt.Errorf("invalid hardware public key: %w", err)
	}
	hardwareKey := Key{
		ID:        deriveID(hardwareKeyIDDomain, hardware),
		PublicKey: hardware,
	}
	r := &Recipient{
		profileID: deriveID(profileIDDomain, hardware),
		hardware:  hardwareKey,
		rand:      cryptographicRandomReader{},
	}
	if recovery == nil {
		return r, nil
	}
	if err := validatePublicKey(*recovery); err != nil {
		return nil, fmt.Errorf("invalid recovery public key: %w", err)
	}
	if bytes.Equal(hardware[:], recovery[:]) {
		return nil, errors.New("hardware and recovery public keys must be independent")
	}
	r.recovery = &Key{
		ID:        deriveID(recoveryKeyIDDomain, *recovery),
		PublicKey: *recovery,
	}
	return r, nil
}

// ParseRecipient parses and canonicalizes an age1yubitouch1... recipient.
func ParseRecipient(s string) (*Recipient, error) {
	name, payload, err := plugin.ParseRecipient(s)
	if err != nil {
		return nil, err
	}
	if name != PluginName {
		return nil, fmt.Errorf("unsupported plugin name %q", name)
	}
	r, err := ParseRecipientPayload(payload)
	if err != nil {
		return nil, err
	}
	if r.String() != s {
		return nil, errors.New("recipient encoding is not canonical")
	}
	return r, nil
}

// ParseRecipientPayload parses the decoded payload passed by the age plugin
// framework.
func ParseRecipientPayload(payload []byte) (*Recipient, error) {
	if len(payload) != recipientPayloadSize && len(payload) != recipientPayloadSize+recoveryPayloadSize {
		return nil, fmt.Errorf("invalid recipient payload size %d", len(payload))
	}
	if payload[0] != ProtocolVersion {
		return nil, fmt.Errorf("unsupported recipient version %d", payload[0])
	}
	if payload[1] != AlgorithmX25519 {
		return nil, fmt.Errorf("unsupported recipient algorithm %d", payload[1])
	}
	flags := payload[2]
	if flags & ^byte(recoveryFlag) != 0 {
		return nil, fmt.Errorf("recipient has unknown flags 0x%02x", flags)
	}
	if payload[3] != 0 {
		return nil, errors.New("recipient reserved byte is non-zero")
	}
	hasRecovery := flags&recoveryFlag != 0
	wantSize := recipientPayloadSize
	if hasRecovery {
		wantSize += recoveryPayloadSize
	}
	if len(payload) != wantSize {
		return nil, errors.New("recipient flags and payload size are inconsistent")
	}

	var encodedProfileID, encodedHardwareKeyID ID
	var hardware PublicKey
	copy(encodedProfileID[:], payload[4:20])
	copy(encodedHardwareKeyID[:], payload[20:36])
	copy(hardware[:], payload[36:68])

	var recovery *PublicKey
	var encodedRecoveryKeyID ID
	if hasRecovery {
		var key PublicKey
		copy(encodedRecoveryKeyID[:], payload[68:84])
		copy(key[:], payload[84:116])
		recovery = &key
	}

	r, err := NewRecipient(hardware, recovery)
	if err != nil {
		return nil, err
	}
	if r.profileID != encodedProfileID {
		return nil, errors.New("recipient profile ID does not match the hardware public key")
	}
	if r.hardware.ID != encodedHardwareKeyID {
		return nil, errors.New("recipient hardware key ID does not match the public key")
	}
	if hasRecovery && r.recovery.ID != encodedRecoveryKeyID {
		return nil, errors.New("recipient recovery key ID does not match the public key")
	}
	return r, nil
}

// String returns the canonical age plugin recipient encoding.
func (r *Recipient) String() string {
	return plugin.EncodeRecipient(PluginName, r.payload())
}

// ProfileID returns the stable profile identifier, which only binds the
// hardware public key.
func (r *Recipient) ProfileID() ID {
	return r.profileID
}

// Hardware returns the hardware wrapping key descriptor.
func (r *Recipient) Hardware() Key {
	return r.hardware
}

// Recovery returns the recovery wrapping key descriptor, if configured.
func (r *Recipient) Recovery() (Key, bool) {
	if r.recovery == nil {
		return Key{}, false
	}
	return *r.recovery, true
}

func (r *Recipient) payload() []byte {
	size := recipientPayloadSize
	flags := byte(0)
	if r.recovery != nil {
		size += recoveryPayloadSize
		flags |= recoveryFlag
	}
	payload := make([]byte, size)
	payload[0] = ProtocolVersion
	payload[1] = AlgorithmX25519
	payload[2] = flags
	copy(payload[4:20], r.profileID[:])
	copy(payload[20:36], r.hardware.ID[:])
	copy(payload[36:68], r.hardware.PublicKey[:])
	if r.recovery != nil {
		copy(payload[68:84], r.recovery.ID[:])
		copy(payload[84:116], r.recovery.PublicKey[:])
	}
	return payload
}

func deriveID(domain string, publicKey PublicKey) ID {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(publicKey[:])
	sum := h.Sum(nil)
	var id ID
	copy(id[:], sum[:len(id)])
	return id
}

func validatePublicKey(key PublicKey) error {
	if !canonicalFieldElement(key) {
		return errors.New("X25519 public key is not canonically encoded")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(key[:])
	if err != nil {
		return errors.New("invalid X25519 public key")
	}
	var validationScalar [32]byte
	validationScalar[0] = 1
	privateKey, err := ecdh.X25519().NewPrivateKey(validationScalar[:])
	if err != nil {
		panic("ageprofile: invalid validation scalar")
	}
	if _, err := privateKey.ECDH(publicKey); err != nil {
		return errors.New("X25519 public key has low order")
	}
	return nil
}

func canonicalFieldElement(key PublicKey) bool {
	var prime PublicKey
	for i := range prime {
		prime[i] = 0xff
	}
	prime[0] = 0xed
	prime[31] = 0x7f
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] < prime[i] {
			return true
		}
		if key[i] > prime[i] {
			return false
		}
	}
	return false
}
