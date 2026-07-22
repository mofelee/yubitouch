package ageprobe

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageprofile"
)

const (
	protocolVersion   = 1
	maxRequestFrame   = 1024
	maxResponseFrame  = 512
	helperFailureCode = 4
)

const internalModeEnvironment = "YUBITOUCH_INTERNAL_AGE_PROBE_HELPER"

// Operation is one public, read-only PKCS#11 operation.
type Operation string

const (
	OperationReadPublic Operation = "read_public"
	OperationProbe      Operation = "probe"
)

// ErrorClass is the complete redacted vocabulary exchanged with the helper.
type ErrorClass string

const (
	ErrorInvalidRequest ErrorClass = "invalid_request"
	ErrorConfiguration  ErrorClass = "configuration_unavailable"
	ErrorNotDetected    ErrorClass = "not_detected"
	ErrorTargetMismatch ErrorClass = "target_mismatch"
	ErrorProbe          ErrorClass = "probe_unavailable"
	ErrorCanceled       ErrorClass = "canceled"
	ErrorTimeout        ErrorClass = "timeout"
	ErrorHelper         ErrorClass = "helper_failed"
)

// ClassError deliberately contains no provider or child-process error text.
type ClassError struct {
	Class ErrorClass
}

func (e *ClassError) Error() string {
	switch e.Class {
	case ErrorInvalidRequest:
		return "age public helper rejected the request"
	case ErrorConfiguration:
		return "age public helper configuration is unavailable"
	case ErrorNotDetected:
		return "configured YubiKey was not detected"
	case ErrorTargetMismatch:
		return "age public helper target does not match"
	case ErrorProbe:
		return "age public helper probe is unavailable"
	case ErrorCanceled:
		return "age public helper was canceled"
	case ErrorTimeout:
		return "age public helper timed out"
	default:
		return "age public helper failed"
	}
}

func (e *ClassError) Unwrap() error {
	if e == nil {
		return nil
	}
	switch e.Class {
	case ErrorNotDetected:
		return agehardware.ErrNotDetected
	case ErrorTargetMismatch:
		return agehardware.ErrTargetMismatch
	case ErrorProbe, ErrorConfiguration, ErrorHelper:
		return agehardware.ErrProbeUnavailable
	case ErrorCanceled:
		return context.Canceled
	case ErrorTimeout:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func classError(class ErrorClass) error {
	if !validErrorClass(class) {
		class = ErrorHelper
	}
	return &ClassError{Class: class}
}

// ErrorClassOf returns only a predefined class.
func ErrorClassOf(err error) ErrorClass {
	var classified *ClassError
	if errors.As(err, &classified) && classified != nil && validErrorClass(classified.Class) {
		return classified.Class
	}
	return ErrorHelper
}

func validErrorClass(class ErrorClass) bool {
	switch class {
	case ErrorInvalidRequest, ErrorConfiguration, ErrorNotDetected,
		ErrorTargetMismatch, ErrorProbe, ErrorCanceled, ErrorTimeout, ErrorHelper:
		return true
	default:
		return false
	}
}

type request struct {
	Operation Operation
	Serial    string
	Slot      string
	PublicKey [32]byte
}

type response struct {
	PublicKey [32]byte
	State     agehardware.ProbeState
}

type wireRequest struct {
	Version   int       `json:"version"`
	Operation Operation `json:"operation"`
	Serial    string    `json:"serial"`
	Slot      string    `json:"slot"`
	PublicKey string    `json:"public_key,omitempty"`
}

type wireResponse struct {
	Version   int                    `json:"version"`
	Status    string                 `json:"status"`
	PublicKey string                 `json:"public_key,omitempty"`
	State     agehardware.ProbeState `json:"state,omitempty"`
	Error     ErrorClass             `json:"error,omitempty"`
}

func marshalRequest(value request) ([]byte, error) {
	if err := validateRequest(value); err != nil {
		return nil, classError(ErrorInvalidRequest)
	}
	wire := wireRequest{
		Version:   protocolVersion,
		Operation: value.Operation,
		Serial:    value.Serial,
		Slot:      value.Slot,
	}
	if value.Operation == OperationProbe {
		wire.PublicKey = base64.RawURLEncoding.EncodeToString(value.PublicKey[:])
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) == 0 || len(encoded) > maxRequestFrame {
		clear(encoded)
		return nil, classError(ErrorInvalidRequest)
	}
	return encoded, nil
}

func unmarshalRequest(encoded []byte) (request, error) {
	if len(encoded) == 0 || len(encoded) > maxRequestFrame {
		return request{}, classError(ErrorInvalidRequest)
	}
	var wire wireRequest
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.Version != protocolVersion {
		return request{}, classError(ErrorInvalidRequest)
	}
	value := request{Operation: wire.Operation, Serial: wire.Serial, Slot: wire.Slot}
	switch wire.Operation {
	case OperationReadPublic:
		if wire.PublicKey != "" {
			return request{}, classError(ErrorInvalidRequest)
		}
	case OperationProbe:
		publicKey, err := decodePublicKey(wire.PublicKey)
		if err != nil {
			return request{}, classError(ErrorInvalidRequest)
		}
		value.PublicKey = publicKey
	default:
		return request{}, classError(ErrorInvalidRequest)
	}
	if err := validateRequest(value); err != nil {
		return request{}, classError(ErrorInvalidRequest)
	}
	return value, nil
}

func validateRequest(value request) error {
	if !validSerial(value.Serial) || !validSlot(value.Slot) {
		return errors.New("invalid target")
	}
	switch value.Operation {
	case OperationReadPublic:
		if value.PublicKey != ([32]byte{}) {
			return errors.New("read-public request contains a public key")
		}
	case OperationProbe:
		if _, err := ageprofile.NewRecipient(ageprofile.PublicKey(value.PublicKey), nil); err != nil {
			return errors.New("invalid probe public key")
		}
	default:
		return errors.New("invalid operation")
	}
	return nil
}

func marshalSuccess(operation Operation, value response) ([]byte, error) {
	wire := wireResponse{Version: protocolVersion, Status: "ok"}
	switch operation {
	case OperationReadPublic:
		if value.State != "" {
			return nil, classError(ErrorHelper)
		}
		if _, err := ageprofile.NewRecipient(ageprofile.PublicKey(value.PublicKey), nil); err != nil {
			return nil, classError(ErrorHelper)
		}
		wire.PublicKey = base64.RawURLEncoding.EncodeToString(value.PublicKey[:])
	case OperationProbe:
		if value.PublicKey != ([32]byte{}) || (value.State != agehardware.Connected && value.State != agehardware.NotDetected) {
			return nil, classError(ErrorHelper)
		}
		wire.State = value.State
	default:
		return nil, classError(ErrorHelper)
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) == 0 || len(encoded) > maxResponseFrame {
		clear(encoded)
		return nil, classError(ErrorHelper)
	}
	return encoded, nil
}

func marshalFailure(class ErrorClass) []byte {
	if !validErrorClass(class) {
		class = ErrorHelper
	}
	encoded, err := json.Marshal(wireResponse{Version: protocolVersion, Status: "error", Error: class})
	if err != nil {
		panic("ageprobe: fixed failure response cannot be encoded")
	}
	return encoded
}

func unmarshalResponse(encoded []byte, operation Operation) (response, error) {
	if len(encoded) == 0 || len(encoded) > maxResponseFrame {
		return response{}, classError(ErrorHelper)
	}
	var wire wireResponse
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.Version != protocolVersion {
		return response{}, classError(ErrorHelper)
	}
	if wire.Status == "error" {
		if wire.PublicKey != "" || wire.State != "" || !validErrorClass(wire.Error) {
			return response{}, classError(ErrorHelper)
		}
		return response{}, classError(wire.Error)
	}
	if wire.Status != "ok" || wire.Error != "" {
		return response{}, classError(ErrorHelper)
	}
	switch operation {
	case OperationReadPublic:
		if wire.State != "" || wire.PublicKey == "" {
			return response{}, classError(ErrorHelper)
		}
		publicKey, err := decodePublicKey(wire.PublicKey)
		if err != nil {
			return response{}, classError(ErrorHelper)
		}
		return response{PublicKey: publicKey}, nil
	case OperationProbe:
		if wire.PublicKey != "" || (wire.State != agehardware.Connected && wire.State != agehardware.NotDetected) {
			return response{}, classError(ErrorHelper)
		}
		return response{State: wire.State}, nil
	default:
		return response{}, classError(ErrorHelper)
	}
}

func decodePublicKey(encoded string) ([32]byte, error) {
	var publicKey [32]byte
	if len(encoded) != base64.RawURLEncoding.EncodedLen(len(publicKey)) {
		return publicKey, errors.New("invalid public key length")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != len(publicKey) || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return publicKey, errors.New("invalid public key encoding")
	}
	copy(publicKey[:], decoded)
	clear(decoded)
	if _, err := ageprofile.NewRecipient(ageprofile.PublicKey(publicKey), nil); err != nil {
		clear(publicKey[:])
		return publicKey, errors.New("invalid public key")
	}
	return publicKey, nil
}

func decodeStrictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
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
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func readFrame(reader io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(limit) {
		return nil, errors.New("invalid frame size")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return nil, err
	}
	return payload, nil
}

func ensureEOF(reader io.Reader) error {
	var extra [1]byte
	n, err := reader.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("trailing bytes")
	}
	return nil
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

func validSerial(serial string) bool {
	parsed, err := strconv.ParseUint(serial, 10, 32)
	return err == nil && parsed != 0 && strconv.FormatUint(parsed, 10) == serial
}

func validSlot(slot string) bool {
	switch slot {
	case "9a", "9c", "9d", "9e":
		return true
	}
	if len(slot) != 2 || strings.ToLower(slot) != slot {
		return false
	}
	parsed, err := strconv.ParseUint(slot, 16, 8)
	return err == nil && parsed >= 0x82 && parsed <= 0x95
}

func contextClass(err error) ErrorClass {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorTimeout
	}
	return ErrorCanceled
}

func hardwareClass(err error) ErrorClass {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return contextClass(err)
	case errors.Is(err, agehardware.ErrNotDetected):
		return ErrorNotDetected
	case errors.Is(err, agehardware.ErrTargetMismatch):
		return ErrorTargetMismatch
	default:
		return ErrorProbe
	}
}
