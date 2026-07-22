package agehelper

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/mofelee/yubitouch/internal/ageprofile"
)

const (
	protocolVersion  = 2
	maxRequestFrame  = 2048
	maxResponseFrame = 512
	fileKeySize      = 16
)

const readyForTouchType = "ready_for_touch"

// Mode selects the single private-key operation performed by the helper.
type Mode string

const (
	ModeHardware Mode = "hardware"
	ModeRecovery Mode = "recovery"
)

const internalModeEnvironment = "YUBITOUCH_INTERNAL_AGE_HELPER"

// ErrorClass is the complete set of errors that can cross the helper pipe.
// It deliberately carries no backend error text.
type ErrorClass string

const (
	ErrorInvalidRequest      ErrorClass = "invalid_request"
	ErrorConfiguration       ErrorClass = "configuration_unavailable"
	ErrorPINProvider         ErrorClass = "pin_provider_failed"
	ErrorHardwareMismatch    ErrorClass = "hardware_mismatch"
	ErrorHardwarePIN         ErrorClass = "hardware_pin_failed"
	ErrorHardware            ErrorClass = "hardware_failed"
	ErrorRecoveryUnavailable ErrorClass = "recovery_unavailable"
	ErrorRecoveryMismatch    ErrorClass = "recovery_mismatch"
	ErrorUnwrap              ErrorClass = "unwrap_failed"
	ErrorCanceled            ErrorClass = "canceled"
	ErrorTimeout             ErrorClass = "timeout"
	ErrorHelper              ErrorClass = "helper_failed"
)

// ClassError is safe to return to the daemon or plugin. Its message is fixed
// and never incorporates stderr, SDK errors, process output, or request data.
type ClassError struct {
	Class ErrorClass
}

func (e *ClassError) Error() string {
	switch e.Class {
	case ErrorInvalidRequest:
		return "age helper rejected the request"
	case ErrorConfiguration:
		return "age helper configuration is unavailable"
	case ErrorPINProvider:
		return "age PIN provider failed"
	case ErrorHardwareMismatch:
		return "age hardware target does not match"
	case ErrorHardwarePIN:
		return "age hardware PIN was rejected"
	case ErrorHardware:
		return "age hardware operation failed"
	case ErrorRecoveryUnavailable:
		return "age recovery provider is unavailable"
	case ErrorRecoveryMismatch:
		return "age recovery identity does not match"
	case ErrorUnwrap:
		return "age file-key unwrap failed"
	case ErrorCanceled:
		return "age helper was canceled"
	case ErrorTimeout:
		return "age helper timed out"
	default:
		return "age helper failed"
	}
}

func classError(class ErrorClass) error {
	return &ClassError{Class: class}
}

func ErrorClassOf(err error) ErrorClass {
	var classified *ClassError
	if errors.As(err, &classified) && validErrorClass(classified.Class) {
		return classified.Class
	}
	return ErrorHelper
}

func validErrorClass(class ErrorClass) bool {
	switch class {
	case ErrorInvalidRequest, ErrorConfiguration, ErrorPINProvider,
		ErrorHardwareMismatch, ErrorHardwarePIN, ErrorHardware,
		ErrorRecoveryUnavailable, ErrorRecoveryMismatch, ErrorUnwrap,
		ErrorCanceled, ErrorTimeout, ErrorHelper:
		return true
	default:
		return false
	}
}

// Request contains one already parsed yubitouch envelope. It is encoded into
// a canonical, bounded representation before crossing the private pipe.
type Request struct {
	Envelope ageprofile.Envelope
}

type wireRequest struct {
	Version  int      `json:"version"`
	Envelope envelope `json:"envelope"`
}

type envelope struct {
	Args []string `json:"args"`
	Body string   `json:"body"`
}

type wireResponse struct {
	Version int          `json:"version"`
	OK      bool         `json:"ok"`
	FileKey *wireFileKey `json:"file_key,omitempty"`
	Error   ErrorClass   `json:"error,omitempty"`
}

type wireReady struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
}

// wireFileKey avoids the immutable Go string created by JSON base64 fields.
// Its custom decoder rejects encoding/json's default short-array zero fill and
// long-array truncation behavior.
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

func marshalRequest(request Request, mode Mode) ([]byte, error) {
	if !validMode(mode) || request.Envelope.Path.String() != string(mode) {
		return nil, classError(ErrorInvalidRequest)
	}
	stanza, err := request.Envelope.Stanza()
	if err != nil {
		return nil, classError(ErrorInvalidRequest)
	}
	wire := wireRequest{
		Version: protocolVersion,
		Envelope: envelope{
			Args: append([]string(nil), stanza.Args...),
			Body: base64.RawURLEncoding.EncodeToString(stanza.Body),
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxRequestFrame {
		clear(encoded)
		return nil, classError(ErrorInvalidRequest)
	}
	return encoded, nil
}

func unmarshalRequest(encoded []byte, mode Mode) (Request, error) {
	if !validMode(mode) || len(encoded) == 0 || len(encoded) > maxRequestFrame {
		return Request{}, classError(ErrorInvalidRequest)
	}
	var wire wireRequest
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.Version != protocolVersion {
		return Request{}, classError(ErrorInvalidRequest)
	}
	if len(wire.Envelope.Args) != 4 {
		return Request{}, classError(ErrorInvalidRequest)
	}
	for _, argument := range wire.Envelope.Args {
		if argument == "" || len(argument) > 64 {
			return Request{}, classError(ErrorInvalidRequest)
		}
	}
	body, err := base64.RawURLEncoding.DecodeString(wire.Envelope.Body)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != wire.Envelope.Body {
		clear(body)
		return Request{}, classError(ErrorInvalidRequest)
	}
	defer clear(body)
	stanza := &age.Stanza{
		Type: ageprofile.StanzaType,
		Args: append([]string(nil), wire.Envelope.Args...),
		Body: append([]byte(nil), body...),
	}
	defer clear(stanza.Body)
	parsed, err := ageprofile.ParseEnvelope(stanza)
	if err != nil || parsed.Path.String() != string(mode) {
		return Request{}, classError(ErrorInvalidRequest)
	}
	return Request{Envelope: parsed}, nil
}

func marshalResponse(fileKey []byte, class ErrorClass) ([]byte, error) {
	response := wireResponse{Version: protocolVersion}
	var encodedKey wireFileKey
	defer clear(encodedKey[:])
	if class != "" {
		if !validErrorClass(class) {
			class = ErrorHelper
		}
		response.Error = class
	} else {
		if len(fileKey) != fileKeySize {
			return nil, classError(ErrorHelper)
		}
		response.OK = true
		copy(encodedKey[:], fileKey)
		response.FileKey = &encodedKey
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > maxResponseFrame {
		clear(encoded)
		return nil, classError(ErrorHelper)
	}
	return encoded, nil
}

func marshalReady() ([]byte, error) {
	encoded, err := json.Marshal(wireReady{Version: protocolVersion, Type: readyForTouchType})
	if err != nil || len(encoded) > maxResponseFrame {
		clear(encoded)
		return nil, classError(ErrorHelper)
	}
	return encoded, nil
}

func unmarshalReady(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maxResponseFrame {
		return classError(ErrorHelper)
	}
	var ready wireReady
	if err := decodeStrictJSON(encoded, &ready); err != nil ||
		ready.Version != protocolVersion || ready.Type != readyForTouchType {
		return classError(ErrorHelper)
	}
	return nil
}

func unmarshalResponse(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > maxResponseFrame {
		return nil, classError(ErrorHelper)
	}
	var response wireResponse
	if err := decodeStrictJSON(encoded, &response); err != nil || response.Version != protocolVersion {
		clearWireFileKey(response.FileKey)
		return nil, classError(ErrorHelper)
	}
	defer clearWireFileKey(response.FileKey)
	if response.OK {
		if response.Error != "" || response.FileKey == nil {
			return nil, classError(ErrorHelper)
		}
		fileKey := make([]byte, fileKeySize)
		copy(fileKey, response.FileKey[:])
		return fileKey, nil
	}
	if response.FileKey != nil || !validErrorClass(response.Error) {
		return nil, classError(ErrorHelper)
	}
	return nil, classError(response.Error)
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

func decodeStrictJSON(encoded []byte, target any) error {
	// Unmarshal parses directly from encoded. json.Decoder keeps an internal
	// copy of the whole frame, which would retain a successful file key in the
	// daemon heap after the caller clears encoded.
	if err := json.Unmarshal(encoded, target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return errors.New("JSON is not canonical")
	}
	clear(canonical)
	return nil
}

func writeFrame(writer io.Writer, payload []byte, limit int) error {
	if len(payload) == 0 || len(payload) > limit {
		return errors.New("invalid frame size")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(writer, header[:]); err != nil {
		return err
	}
	return writeFull(writer, payload)
}

func readFrame(reader io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, errors.New("cannot read frame header")
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(limit) {
		return nil, errors.New("invalid frame size")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return nil, errors.New("cannot read frame body")
	}
	return payload, nil
}

func ensureEOF(reader io.Reader) error {
	var extra [1]byte
	n, err := reader.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("frame has trailing data")
	}
	return nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func validMode(mode Mode) bool {
	return mode == ModeHardware || mode == ModeRecovery
}

func parseMode(value string) (Mode, bool) {
	mode := Mode(strings.TrimSpace(value))
	return mode, validMode(mode) && string(mode) == value
}
