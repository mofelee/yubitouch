package ageipc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/mofelee/yubitouch/internal/ageprofile"
)

var errInvalidFrameSize = errors.New("invalid frame size")

const (
	// ProtocolVersion is the version of the local daemon wire protocol.
	ProtocolVersion = 1
	// MaxFrameSize bounds every request and response before allocation.
	MaxFrameSize = 4096
	// MaxStanzas permits exactly one hardware stanza and at most one recovery stanza.
	MaxStanzas   = 2
	fileKeySize  = 16
	maxJSONDepth = 8
)

// ErrorClass is the complete, redacted error vocabulary exposed on the wire.
type ErrorClass string

const (
	ClassInvalidRequest      ErrorClass = "invalid_request"
	ClassConfiguration       ErrorClass = "configuration"
	ClassUnauthorized        ErrorClass = "unauthorized"
	ClassBusy                ErrorClass = "busy"
	ClassCanceled            ErrorClass = "canceled"
	ClassTimeout             ErrorClass = "timeout"
	ClassDeviceNotDetected   ErrorClass = "device_not_detected"
	ClassProbeUnavailable    ErrorClass = "probe_unavailable"
	ClassTargetMismatch      ErrorClass = "target_mismatch"
	ClassPINFailed           ErrorClass = "pin_failed"
	ClassHardwareFailed      ErrorClass = "hardware_failed"
	ClassRecoveryUnavailable ErrorClass = "recovery_unavailable"
	ClassRecoveryFailed      ErrorClass = "recovery_failed"
	ClassInternal            ErrorClass = "internal"
	ClassProtocolFailure     ErrorClass = "protocol_failure"
	ClassDaemonUnavailable   ErrorClass = "daemon_unavailable"
)

// Error is a safe client error. It never contains daemon or transport details.
type Error struct {
	Class ErrorClass
}

func (e *Error) Error() string {
	if e == nil || !validErrorClass(e.Class) {
		return "YubiTouch age request failed"
	}
	return "YubiTouch age request failed: " + string(e.Class)
}

// ClassOf extracts a predefined error class.
func ClassOf(err error) (ErrorClass, bool) {
	var wireErr *Error
	if !errors.As(err, &wireErr) || wireErr == nil || !validErrorClass(wireErr.Class) {
		return "", false
	}
	return wireErr.Class, true
}

func protocolError(class ErrorClass) error {
	if !validErrorClass(class) {
		class = ClassInternal
	}
	return &Error{Class: class}
}

func validErrorClass(class ErrorClass) bool {
	switch class {
	case ClassInvalidRequest,
		ClassConfiguration,
		ClassUnauthorized,
		ClassBusy,
		ClassCanceled,
		ClassTimeout,
		ClassDeviceNotDetected,
		ClassProbeUnavailable,
		ClassTargetMismatch,
		ClassPINFailed,
		ClassHardwareFailed,
		ClassRecoveryUnavailable,
		ClassRecoveryFailed,
		ClassInternal,
		ClassProtocolFailure,
		ClassDaemonUnavailable:
		return true
	default:
		return false
	}
}

type wireRequest struct {
	Version       int            `json:"version"`
	Operation     string         `json:"operation"`
	ProfileID     string         `json:"profile_id"`
	HardwareKeyID string         `json:"hardware_key_id"`
	Stanzas       []wireEnvelope `json:"stanzas"`
}

type wireEnvelope struct {
	Path               string `json:"path"`
	ProfileID          string `json:"profile_id"`
	KeyID              string `json:"key_id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Ciphertext         string `json:"ciphertext"`
}

type wireResponse struct {
	Version int          `json:"version"`
	Status  string       `json:"status"`
	FileKey *wireFileKey `json:"file_key,omitempty"`
	Error   ErrorClass   `json:"error,omitempty"`
}

// wireFileKey keeps key material in mutable arrays instead of an immutable
// base64 Go string. Its decoder also enforces the exact array length that the
// standard fixed-array decoder otherwise does not enforce.
type wireFileKey [fileKeySize]uint8

func (k *wireFileKey) UnmarshalJSON(data []byte) error {
	if k == nil {
		return errors.New("file key destination is nil")
	}
	var values []uint16
	defer func() { clearUint16(values) }()
	if err := json.Unmarshal(data, &values); err != nil {
		return errors.New("file key is not a byte array")
	}
	if len(values) != fileKeySize {
		return errors.New("file key has an invalid length")
	}
	var decoded wireFileKey
	defer clear(decoded[:])
	for index, value := range values {
		if value > 255 {
			return errors.New("file key value is outside the byte range")
		}
		decoded[index] = byte(value)
	}
	*k = decoded
	return nil
}

func marshalRequest(request ageprofile.UnwrapRequest) ([]byte, error) {
	wire, err := requestToWire(request)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) > MaxFrameSize {
		clear(payload)
		return nil, errors.New("request cannot be encoded")
	}
	return payload, nil
}

func unmarshalRequest(payload []byte) (ageprofile.UnwrapRequest, error) {
	var wire wireRequest
	if err := strictJSON(payload, &wire); err != nil {
		return ageprofile.UnwrapRequest{}, errors.New("invalid request encoding")
	}
	return wireToRequest(wire)
}

func requestToWire(request ageprofile.UnwrapRequest) (wireRequest, error) {
	wire := wireRequest{
		Version:       ProtocolVersion,
		Operation:     "unwrap",
		ProfileID:     request.ProfileID.String(),
		HardwareKeyID: request.HardwareKeyID.String(),
		Stanzas:       make([]wireEnvelope, 0, MaxStanzas),
	}
	hardware, err := envelopeToWire(request.Hardware)
	if err != nil {
		return wireRequest{}, errors.New("invalid hardware envelope")
	}
	wire.Stanzas = append(wire.Stanzas, hardware)
	if request.Recovery != nil {
		recovery, err := envelopeToWire(*request.Recovery)
		if err != nil {
			return wireRequest{}, errors.New("invalid recovery envelope")
		}
		wire.Stanzas = append(wire.Stanzas, recovery)
	}
	if _, err := wireToRequest(wire); err != nil {
		return wireRequest{}, err
	}
	return wire, nil
}

func wireToRequest(wire wireRequest) (ageprofile.UnwrapRequest, error) {
	if wire.Version != ProtocolVersion || wire.Operation != "unwrap" {
		return ageprofile.UnwrapRequest{}, errors.New("unsupported request")
	}
	profileID, err := decodeID(wire.ProfileID)
	if err != nil {
		return ageprofile.UnwrapRequest{}, errors.New("invalid profile ID")
	}
	hardwareKeyID, err := decodeID(wire.HardwareKeyID)
	if err != nil {
		return ageprofile.UnwrapRequest{}, errors.New("invalid hardware key ID")
	}
	if len(wire.Stanzas) < 1 || len(wire.Stanzas) > MaxStanzas {
		return ageprofile.UnwrapRequest{}, errors.New("invalid stanza count")
	}
	request := ageprofile.UnwrapRequest{ProfileID: profileID, HardwareKeyID: hardwareKeyID}
	var hardwareFound, recoveryFound bool
	for _, encoded := range wire.Stanzas {
		envelope, err := wireToEnvelope(encoded)
		if err != nil {
			return ageprofile.UnwrapRequest{}, errors.New("invalid stanza")
		}
		if envelope.ProfileID != profileID {
			return ageprofile.UnwrapRequest{}, errors.New("stanza profile mismatch")
		}
		switch envelope.Path {
		case ageprofile.PathHardware:
			if hardwareFound || envelope.KeyID != hardwareKeyID {
				return ageprofile.UnwrapRequest{}, errors.New("invalid hardware stanza")
			}
			request.Hardware = envelope
			hardwareFound = true
		case ageprofile.PathRecovery:
			if recoveryFound || envelope.KeyID == hardwareKeyID {
				return ageprofile.UnwrapRequest{}, errors.New("invalid recovery stanza")
			}
			copy := envelope
			request.Recovery = &copy
			recoveryFound = true
		default:
			return ageprofile.UnwrapRequest{}, errors.New("invalid stanza path")
		}
	}
	if !hardwareFound {
		return ageprofile.UnwrapRequest{}, errors.New("hardware stanza is required")
	}
	return request, nil
}

func envelopeToWire(envelope ageprofile.Envelope) (wireEnvelope, error) {
	stanza, err := envelope.Stanza()
	if err != nil {
		return wireEnvelope{}, err
	}
	parsed, err := ageprofile.ParseEnvelope(stanza)
	if err != nil || parsed != envelope {
		return wireEnvelope{}, errors.New("envelope is not canonical")
	}
	return wireEnvelope{
		Path:               envelope.Path.String(),
		ProfileID:          envelope.ProfileID.String(),
		KeyID:              envelope.KeyID.String(),
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(envelope.EphemeralPublicKey[:]),
		Ciphertext:         base64.RawURLEncoding.EncodeToString(envelope.Ciphertext[:]),
	}, nil
}

func wireToEnvelope(wire wireEnvelope) (ageprofile.Envelope, error) {
	if len(wire.Path) > len("hardware") || len(wire.ProfileID) != 32 || len(wire.KeyID) != 32 ||
		len(wire.EphemeralPublicKey) != base64.RawURLEncoding.EncodedLen(32) ||
		len(wire.Ciphertext) != base64.RawURLEncoding.EncodedLen(32) {
		return ageprofile.Envelope{}, errors.New("invalid envelope field length")
	}
	var path ageprofile.Path
	switch wire.Path {
	case "hardware":
		path = ageprofile.PathHardware
	case "recovery":
		path = ageprofile.PathRecovery
	default:
		return ageprofile.Envelope{}, errors.New("invalid envelope path")
	}
	profileID, err := decodeID(wire.ProfileID)
	if err != nil {
		return ageprofile.Envelope{}, err
	}
	keyID, err := decodeID(wire.KeyID)
	if err != nil {
		return ageprofile.Envelope{}, err
	}
	publicKey, err := decodeBase64(wire.EphemeralPublicKey, 32)
	if err != nil {
		return ageprofile.Envelope{}, err
	}
	defer clear(publicKey)
	ciphertext, err := decodeBase64(wire.Ciphertext, 32)
	if err != nil {
		return ageprofile.Envelope{}, err
	}
	defer clear(ciphertext)
	envelope := ageprofile.Envelope{Path: path, ProfileID: profileID, KeyID: keyID}
	copy(envelope.EphemeralPublicKey[:], publicKey)
	copy(envelope.Ciphertext[:], ciphertext)
	stanza, err := envelope.Stanza()
	if err != nil {
		return ageprofile.Envelope{}, err
	}
	parsed, err := ageprofile.ParseEnvelope(stanza)
	if err != nil || parsed != envelope {
		return ageprofile.Envelope{}, errors.New("envelope is not canonical")
	}
	return parsed, nil
}

func decodeID(value string) (ageprofile.ID, error) {
	if len(value) != 32 {
		return ageprofile.ID{}, errors.New("invalid identifier length")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return ageprofile.ID{}, errors.New("invalid identifier encoding")
	}
	defer clear(decoded)
	var id ageprofile.ID
	copy(id[:], decoded)
	if id == (ageprofile.ID{}) || id.String() != value {
		return ageprofile.ID{}, errors.New("identifier is not canonical")
	}
	return id, nil
}

func decodeBase64(value string, size int) ([]byte, error) {
	if len(value) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, errors.New("invalid base64 length")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("invalid base64 encoding")
	}
	return decoded, nil
}

func marshalSuccess(fileKey []byte) ([]byte, error) {
	if len(fileKey) != fileKeySize {
		return nil, errors.New("invalid file key size")
	}
	var encodedKey wireFileKey
	defer clear(encodedKey[:])
	copy(encodedKey[:], fileKey)
	return json.Marshal(wireResponse{
		Version: ProtocolVersion,
		Status:  "ok",
		FileKey: &encodedKey,
	})
}

func marshalFailure(class ErrorClass) []byte {
	if !validErrorClass(class) {
		class = ClassInternal
	}
	payload, err := json.Marshal(wireResponse{Version: ProtocolVersion, Status: "error", Error: class})
	if err != nil {
		panic("ageipc: fixed error response cannot be encoded")
	}
	return payload
}

func unmarshalResponse(payload []byte) ([]byte, error) {
	var response wireResponse
	if err := strictJSON(payload, &response); err != nil || response.Version != ProtocolVersion {
		clearWireFileKey(response.FileKey)
		return nil, protocolError(ClassProtocolFailure)
	}
	defer clearWireFileKey(response.FileKey)
	fileKeyPresent, err := responseFileKeyPresent(payload)
	if err != nil {
		return nil, protocolError(ClassProtocolFailure)
	}
	switch response.Status {
	case "ok":
		if response.Error != "" || !fileKeyPresent || response.FileKey == nil {
			return nil, protocolError(ClassProtocolFailure)
		}
		fileKey := make([]byte, fileKeySize)
		copy(fileKey, response.FileKey[:])
		return fileKey, nil
	case "error":
		if fileKeyPresent || response.FileKey != nil || !validErrorClass(response.Error) {
			return nil, protocolError(ClassProtocolFailure)
		}
		return nil, protocolError(response.Error)
	default:
		return nil, protocolError(ClassProtocolFailure)
	}
}

func responseFileKeyPresent(payload []byte) (bool, error) {
	var fields map[string]json.RawMessage
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	if err := json.Unmarshal(payload, &fields); err != nil {
		return false, err
	}
	value, present := fields["file_key"]
	if present && bytes.Equal(value, []byte("null")) {
		return true, errors.New("file key must not be null")
	}
	return present, nil
}

func clearWireFileKey(key *wireFileKey) {
	if key != nil {
		clear(key[:])
	}
}

func clearUint16(values []uint16) {
	for index := range values {
		values[index] = 0
	}
}

func readFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameSize {
		return nil, errInvalidFrameSize
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return nil, err
	}
	return payload, nil
}

func writeFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxFrameSize {
		return errInvalidFrameSize
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func strictJSON(payload []byte, target any) error {
	if len(payload) == 0 || len(payload) > MaxFrameSize || !utf8.Valid(payload) {
		return errors.New("invalid JSON payload")
	}
	checker := json.NewDecoder(bytes.NewReader(payload))
	if err := scanJSONValue(checker, 0); err != nil {
		return err
	}
	if token, err := checker.Token(); err != io.EOF || token != nil {
		return errors.New("trailing JSON value")
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
