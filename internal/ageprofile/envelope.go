package ageprofile

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	fileKeySize       = 16
	wrappedKeySize    = fileKeySize + chacha20poly1305.Overhead
	envelopeBodySize  = 32 + wrappedKeySize
	stanzaVersion     = "v1"
	kdfSaltDomain     = "age-plugin-yubitouch/v1/x25519-salt"
	kdfInfoDomain     = "age-plugin-yubitouch/v1/x25519-wrap"
	associatedDataTag = "age-plugin-yubitouch/v1/stanza-ad"
)

// Path identifies the hardware or recovery wrapping path.
type Path byte

const (
	PathHardware Path = 1
	PathRecovery Path = 2
)

func (p Path) String() string {
	switch p {
	case PathHardware:
		return "hardware"
	case PathRecovery:
		return "recovery"
	default:
		return ""
	}
}

// Envelope is the canonical binary content of one yubitouch recipient stanza.
type Envelope struct {
	Path               Path
	ProfileID          ID
	KeyID              ID
	EphemeralPublicKey PublicKey
	Ciphertext         [wrappedKeySize]byte
}

// ParseEnvelope strictly parses one yubitouch recipient stanza.
func ParseEnvelope(stanza *age.Stanza) (Envelope, error) {
	if stanza == nil {
		return Envelope{}, errors.New("recipient stanza is nil")
	}
	if stanza.Type != StanzaType {
		return Envelope{}, fmt.Errorf("unexpected recipient stanza type %q", stanza.Type)
	}
	if len(stanza.Args) != 4 {
		return Envelope{}, fmt.Errorf("yubitouch stanza has %d arguments, want 4", len(stanza.Args))
	}
	if stanza.Args[0] != stanzaVersion {
		return Envelope{}, fmt.Errorf("unsupported yubitouch stanza version %q", stanza.Args[0])
	}
	path, err := parsePath(stanza.Args[1])
	if err != nil {
		return Envelope{}, err
	}
	profileID, err := parseID(stanza.Args[2])
	if err != nil {
		return Envelope{}, fmt.Errorf("invalid stanza profile ID: %w", err)
	}
	keyID, err := parseID(stanza.Args[3])
	if err != nil {
		return Envelope{}, fmt.Errorf("invalid stanza key ID: %w", err)
	}
	if len(stanza.Body) != envelopeBodySize {
		return Envelope{}, fmt.Errorf("yubitouch stanza body has %d bytes, want %d", len(stanza.Body), envelopeBodySize)
	}
	envelope := Envelope{
		Path:      path,
		ProfileID: profileID,
		KeyID:     keyID,
	}
	copy(envelope.EphemeralPublicKey[:], stanza.Body[:32])
	copy(envelope.Ciphertext[:], stanza.Body[32:])
	if err := envelope.validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// Stanza serializes an envelope as a canonical age recipient stanza.
func (e Envelope) Stanza() (*age.Stanza, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	body := make([]byte, envelopeBodySize)
	copy(body[:32], e.EphemeralPublicKey[:])
	copy(body[32:], e.Ciphertext[:])
	return &age.Stanza{
		Type: StanzaType,
		Args: []string{
			stanzaVersion,
			e.Path.String(),
			e.ProfileID.String(),
			e.KeyID.String(),
		},
		Body: body,
	}, nil
}

func (e Envelope) validate() error {
	if e.Path != PathHardware && e.Path != PathRecovery {
		return fmt.Errorf("unknown yubitouch path %d", e.Path)
	}
	if e.ProfileID.isZero() {
		return errors.New("stanza profile ID is zero")
	}
	if e.KeyID.isZero() {
		return errors.New("stanza key ID is zero")
	}
	if err := validatePublicKey(e.EphemeralPublicKey); err != nil {
		return fmt.Errorf("invalid stanza ephemeral public key: %w", err)
	}
	return nil
}

func parsePath(value string) (Path, error) {
	switch value {
	case "hardware":
		return PathHardware, nil
	case "recovery":
		return PathRecovery, nil
	default:
		return 0, fmt.Errorf("unknown yubitouch stanza path %q", value)
	}
}

func parseID(value string) (ID, error) {
	if len(value) != 32 {
		return ID{}, fmt.Errorf("identifier has %d characters, want 32", len(value))
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return ID{}, errors.New("identifier is not hexadecimal")
	}
	var id ID
	copy(id[:], decoded)
	if id.String() != value {
		return ID{}, errors.New("identifier is not canonical lowercase hexadecimal")
	}
	if id.isZero() {
		return ID{}, errors.New("identifier is zero")
	}
	return id, nil
}

type randomReader interface {
	Read([]byte) (int, error)
}

type cryptographicRandomReader struct{}

func (cryptographicRandomReader) Read(p []byte) (int, error) {
	return rand.Read(p)
}

var _ age.Recipient = (*Recipient)(nil)

// Wrap wraps the same 16-byte age file key for the hardware path and, when
// configured, independently for the recovery path.
func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	if len(fileKey) != fileKeySize {
		return nil, fmt.Errorf("age file key has %d bytes, want %d", len(fileKey), fileKeySize)
	}
	if r.rand == nil {
		return nil, errors.New("cryptographic random source is unavailable")
	}
	hardwareEnvelope, err := r.wrapForKey(PathHardware, r.hardware, fileKey)
	if err != nil {
		return nil, fmt.Errorf("wrap hardware file key: %w", err)
	}
	hardwareStanza, err := hardwareEnvelope.Stanza()
	if err != nil {
		return nil, err
	}
	stanzas := []*age.Stanza{hardwareStanza}
	if r.recovery == nil {
		return stanzas, nil
	}
	recoveryEnvelope, err := r.wrapForKey(PathRecovery, *r.recovery, fileKey)
	if err != nil {
		return nil, fmt.Errorf("wrap recovery file key: %w", err)
	}
	recoveryStanza, err := recoveryEnvelope.Stanza()
	if err != nil {
		return nil, err
	}
	return append(stanzas, recoveryStanza), nil
}

func (r *Recipient) wrapForKey(path Path, key Key, fileKey []byte) (Envelope, error) {
	var scalar [32]byte
	if _, err := io.ReadFull(r.rand, scalar[:]); err != nil {
		return Envelope{}, fmt.Errorf("read ephemeral key: %w", err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(scalar[:])
	clear(scalar[:])
	if err != nil {
		return Envelope{}, fmt.Errorf("create ephemeral key: %w", err)
	}
	recipientPublicKey, err := ecdh.X25519().NewPublicKey(key.PublicKey[:])
	if err != nil {
		return Envelope{}, errors.New("invalid recipient public key")
	}
	sharedSecret, err := privateKey.ECDH(recipientPublicKey)
	if err != nil {
		return Envelope{}, errors.New("X25519 key agreement failed")
	}
	defer clear(sharedSecret)

	envelope := Envelope{
		Path:      path,
		ProfileID: r.profileID,
		KeyID:     key.ID,
	}
	copy(envelope.EphemeralPublicKey[:], privateKey.PublicKey().Bytes())
	wrappingKey, err := deriveWrappingKey(sharedSecret, envelope, key.PublicKey)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(wrappingKey[:])
	aead, err := chacha20poly1305.New(wrappingKey[:])
	if err != nil {
		return Envelope{}, fmt.Errorf("initialize file key cipher: %w", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	ciphertext := aead.Seal(nil, nonce[:], fileKey, associatedData(envelope, key.PublicKey))
	if len(ciphertext) != len(envelope.Ciphertext) {
		return Envelope{}, errors.New("unexpected wrapped file key size")
	}
	copy(envelope.Ciphertext[:], ciphertext)
	clear(ciphertext)
	return envelope, nil
}

// UnwrapWithPrivateKey unwraps an envelope with a software X25519 private key.
func UnwrapWithPrivateKey(envelope Envelope, privateKey *ecdh.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("X25519 private key is nil")
	}
	if privateKey.Curve() != ecdh.X25519() {
		return nil, errors.New("private key is not X25519")
	}
	publicBytes := privateKey.PublicKey().Bytes()
	if len(publicBytes) != len(PublicKey{}) {
		return nil, errors.New("invalid X25519 public key size")
	}
	var recipientPublicKey PublicKey
	copy(recipientPublicKey[:], publicBytes)
	ephemeralPublicKey, err := ecdh.X25519().NewPublicKey(envelope.EphemeralPublicKey[:])
	if err != nil {
		return nil, errors.New("invalid stanza ephemeral public key")
	}
	sharedSecret, err := privateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, errors.New("X25519 key agreement failed")
	}
	defer clear(sharedSecret)
	return UnwrapWithSharedSecret(envelope, recipientPublicKey, sharedSecret)
}

// UnwrapWithSharedSecret unwraps an envelope after an external X25519 backend
// performs key agreement. The recipient public key remains part of both the
// KDF and the associated data.
func UnwrapWithSharedSecret(envelope Envelope, recipientPublicKey PublicKey, sharedSecret []byte) ([]byte, error) {
	if err := envelope.validate(); err != nil {
		return nil, err
	}
	if err := validatePublicKey(recipientPublicKey); err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("X25519 shared secret has %d bytes, want 32", len(sharedSecret))
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(sharedSecret, zero[:]) == 1 {
		return nil, errors.New("X25519 shared secret is zero")
	}
	expectedKeyID := deriveID(recoveryKeyIDDomain, recipientPublicKey)
	if envelope.Path == PathHardware {
		expectedKeyID = deriveID(hardwareKeyIDDomain, recipientPublicKey)
		if envelope.ProfileID != deriveID(profileIDDomain, recipientPublicKey) {
			return nil, errors.New("stanza profile ID does not match the hardware public key")
		}
	}
	if envelope.KeyID != expectedKeyID {
		return nil, errors.New("stanza key ID does not match the recipient public key")
	}

	wrappingKey, err := deriveWrappingKey(sharedSecret, envelope, recipientPublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey[:])
	aead, err := chacha20poly1305.New(wrappingKey[:])
	if err != nil {
		return nil, fmt.Errorf("initialize file key cipher: %w", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	fileKey, err := aead.Open(nil, nonce[:], envelope.Ciphertext[:], associatedData(envelope, recipientPublicKey))
	if err != nil {
		return nil, errors.New("wrapped file key authentication failed")
	}
	if len(fileKey) != fileKeySize {
		clear(fileKey)
		return nil, errors.New("unwrapped age file key has an invalid size")
	}
	return fileKey, nil
}

func deriveWrappingKey(sharedSecret []byte, envelope Envelope, recipientPublicKey PublicKey) ([32]byte, error) {
	h := sha256.New()
	h.Write([]byte(kdfSaltDomain))
	h.Write([]byte{0})
	h.Write(envelope.EphemeralPublicKey[:])
	h.Write(recipientPublicKey[:])
	salt := h.Sum(nil)
	reader := hkdf.New(sha256.New, sharedSecret, salt, []byte(kdfInfoDomain))
	var key [chacha20poly1305.KeySize]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("derive wrapping key: %w", err)
	}
	return key, nil
}

func associatedData(envelope Envelope, recipientPublicKey PublicKey) []byte {
	data := make([]byte, 0, len(associatedDataTag)+4+len(envelope.ProfileID)+len(envelope.KeyID)+64)
	data = append(data, associatedDataTag...)
	data = append(data, 0, ProtocolVersion, AlgorithmX25519, byte(envelope.Path))
	data = append(data, envelope.ProfileID[:]...)
	data = append(data, envelope.KeyID[:]...)
	data = append(data, envelope.EphemeralPublicKey[:]...)
	data = append(data, recipientPublicKey[:]...)
	return data
}
