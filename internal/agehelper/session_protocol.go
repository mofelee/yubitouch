package agehelper

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"filippo.io/age"
	"github.com/mofelee/yubitouch/internal/ageprofile"
)

const (
	sessionProtocolVersion  = 2
	identifierSize          = 16
	encodedIdentifierSize   = identifierSize * 2
	maxSessionRequestFrame  = maxRequestFrame + 256
	maxSessionResponseFrame = maxResponseFrame + 256
)

const (
	sessionRequestType       = "request"
	sessionReadyType         = "session_ready"
	sessionReadyForTouchType = "ready_for_touch"
	sessionContinueType      = "continue"
	sessionResultType        = "result"
)

type sessionIdentifier [identifierSize]byte
type requestIdentifier [identifierSize]byte
type continuationIdentifier [identifierSize]byte

func newSessionIdentifier() (sessionIdentifier, error) {
	var identifier sessionIdentifier
	if err := fillIdentifier(identifier[:]); err != nil {
		return sessionIdentifier{}, err
	}
	return identifier, nil
}

func newRequestIdentifier() (requestIdentifier, error) {
	var identifier requestIdentifier
	if err := fillIdentifier(identifier[:]); err != nil {
		return requestIdentifier{}, err
	}
	return identifier, nil
}

func newContinuationIdentifier() (continuationIdentifier, error) {
	var identifier continuationIdentifier
	if err := fillIdentifier(identifier[:]); err != nil {
		return continuationIdentifier{}, err
	}
	return identifier, nil
}

func fillIdentifier(identifier []byte) error {
	if len(identifier) != identifierSize {
		return classError(ErrorHelper)
	}
	for {
		if _, err := rand.Read(identifier); err != nil {
			clear(identifier)
			return classError(ErrorHelper)
		}
		if identifierIsValid(identifier) {
			return nil
		}
	}
}

func (identifier sessionIdentifier) MarshalJSON() ([]byte, error) {
	return marshalIdentifierJSON(identifier[:])
}

func (identifier *sessionIdentifier) UnmarshalJSON(encoded []byte) error {
	if identifier == nil {
		return errors.New("session identifier destination is nil")
	}
	decoded, err := unmarshalIdentifierJSON(encoded)
	if err != nil {
		clear(identifier[:])
		return err
	}
	copy(identifier[:], decoded[:])
	clear(decoded[:])
	return nil
}

func (identifier requestIdentifier) MarshalJSON() ([]byte, error) {
	return marshalIdentifierJSON(identifier[:])
}

func (identifier *requestIdentifier) UnmarshalJSON(encoded []byte) error {
	if identifier == nil {
		return errors.New("request identifier destination is nil")
	}
	decoded, err := unmarshalIdentifierJSON(encoded)
	if err != nil {
		clear(identifier[:])
		return err
	}
	copy(identifier[:], decoded[:])
	clear(decoded[:])
	return nil
}

func (identifier continuationIdentifier) MarshalJSON() ([]byte, error) {
	return marshalIdentifierJSON(identifier[:])
}

func (identifier *continuationIdentifier) UnmarshalJSON(encoded []byte) error {
	if identifier == nil {
		return errors.New("continuation identifier destination is nil")
	}
	decoded, err := unmarshalIdentifierJSON(encoded)
	if err != nil {
		clear(identifier[:])
		return err
	}
	copy(identifier[:], decoded[:])
	clear(decoded[:])
	return nil
}

func marshalIdentifierJSON(identifier []byte) ([]byte, error) {
	if !identifierIsValid(identifier) {
		return nil, errors.New("identifier is invalid")
	}
	encoded := make([]byte, encodedIdentifierSize+2)
	encoded[0] = '"'
	hex.Encode(encoded[1:1+encodedIdentifierSize], identifier)
	encoded[len(encoded)-1] = '"'
	return encoded, nil
}

func unmarshalIdentifierJSON(encoded []byte) ([identifierSize]byte, error) {
	var identifier [identifierSize]byte
	if len(encoded) != encodedIdentifierSize+2 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return identifier, errors.New("identifier encoding is invalid")
	}
	for _, value := range encoded[1 : len(encoded)-1] {
		if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')) {
			return identifier, errors.New("identifier is not lowercase hexadecimal")
		}
	}
	if _, err := hex.Decode(identifier[:], encoded[1:len(encoded)-1]); err != nil || !identifierIsValid(identifier[:]) {
		clear(identifier[:])
		return [identifierSize]byte{}, errors.New("identifier value is invalid")
	}
	return identifier, nil
}

func identifierIsValid(identifier []byte) bool {
	if len(identifier) != identifierSize {
		return false
	}
	var combined byte
	for _, value := range identifier {
		combined |= value
	}
	return combined != 0
}

type wireSessionRequest struct {
	Version   int               `json:"version"`
	Type      string            `json:"type"`
	SessionID sessionIdentifier `json:"session_id"`
	RequestID requestIdentifier `json:"request_id"`
	Envelope  envelope          `json:"envelope"`
}

type wireSessionReady struct {
	Version   int               `json:"version"`
	Type      string            `json:"type"`
	SessionID sessionIdentifier `json:"session_id"`
	RequestID requestIdentifier `json:"request_id"`
}

type wireSessionReadyForTouch struct {
	Version   int               `json:"version"`
	Type      string            `json:"type"`
	SessionID sessionIdentifier `json:"session_id"`
	RequestID requestIdentifier `json:"request_id"`
}

type wireSessionContinue struct {
	Version        int                    `json:"version"`
	Type           string                 `json:"type"`
	SessionID      sessionIdentifier      `json:"session_id"`
	RequestID      requestIdentifier      `json:"request_id"`
	ContinuationID continuationIdentifier `json:"continuation_id"`
}

type wireSessionResult struct {
	Version        int                     `json:"version"`
	Type           string                  `json:"type"`
	SessionID      sessionIdentifier       `json:"session_id"`
	RequestID      requestIdentifier       `json:"request_id"`
	ContinuationID *continuationIdentifier `json:"continuation_id,omitempty"`
	OK             bool                    `json:"ok"`
	FileKey        *wireFileKey            `json:"file_key,omitempty"`
	Error          ErrorClass              `json:"error,omitempty"`
}

func marshalSessionRequest(sessionID sessionIdentifier, requestID requestIdentifier, request Request) ([]byte, error) {
	if request.Envelope.Path != ageprofile.PathHardware {
		return nil, classError(ErrorInvalidRequest)
	}
	stanza, err := request.Envelope.Stanza()
	if err != nil {
		return nil, classError(ErrorInvalidRequest)
	}
	wire := wireSessionRequest{
		Version:   sessionProtocolVersion,
		Type:      sessionRequestType,
		SessionID: sessionID,
		RequestID: requestID,
		Envelope: envelope{
			Args: append([]string(nil), stanza.Args...),
			Body: base64.RawURLEncoding.EncodeToString(stanza.Body),
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxSessionRequestFrame {
		clear(encoded)
		return nil, classError(ErrorInvalidRequest)
	}
	return encoded, nil
}

func unmarshalSessionRequest(encoded []byte, expectedSessionID sessionIdentifier) (requestIdentifier, Request, error) {
	if len(encoded) == 0 || len(encoded) > maxSessionRequestFrame || !identifierIsValid(expectedSessionID[:]) {
		return requestIdentifier{}, Request{}, classError(ErrorInvalidRequest)
	}
	var wire wireSessionRequest
	if err := decodeStrictJSON(encoded, &wire); err != nil ||
		wire.Version != sessionProtocolVersion || wire.Type != sessionRequestType || wire.SessionID != expectedSessionID ||
		!identifierIsValid(wire.RequestID[:]) {
		return requestIdentifier{}, Request{}, classError(ErrorInvalidRequest)
	}
	request, err := sessionRequestFromEnvelope(wire.Envelope)
	if err != nil {
		return requestIdentifier{}, Request{}, err
	}
	return wire.RequestID, request, nil
}

func sessionRequestFromEnvelope(encoded envelope) (Request, error) {
	if len(encoded.Args) != 4 {
		return Request{}, classError(ErrorInvalidRequest)
	}
	for _, argument := range encoded.Args {
		if argument == "" || len(argument) > 64 {
			return Request{}, classError(ErrorInvalidRequest)
		}
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded.Body)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != encoded.Body {
		clear(body)
		return Request{}, classError(ErrorInvalidRequest)
	}
	defer clear(body)
	stanza := &age.Stanza{
		Type: ageprofile.StanzaType,
		Args: append([]string(nil), encoded.Args...),
		Body: append([]byte(nil), body...),
	}
	defer clear(stanza.Body)
	parsed, err := ageprofile.ParseEnvelope(stanza)
	if err != nil || parsed.Path != ageprofile.PathHardware {
		return Request{}, classError(ErrorInvalidRequest)
	}
	return Request{Envelope: parsed}, nil
}

func marshalSessionReady(sessionID sessionIdentifier, requestID requestIdentifier) ([]byte, error) {
	encoded, err := json.Marshal(wireSessionReady{
		Version: sessionProtocolVersion, Type: sessionReadyType, SessionID: sessionID, RequestID: requestID,
	})
	return checkedSessionResponse(encoded, err)
}

func unmarshalSessionReady(encoded []byte, expectedSessionID sessionIdentifier, expectedRequestID requestIdentifier) error {
	if !validSessionResponseInput(encoded, expectedSessionID, expectedRequestID) {
		return classError(ErrorHelper)
	}
	var wire wireSessionReady
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.Version != sessionProtocolVersion ||
		wire.Type != sessionReadyType || wire.SessionID != expectedSessionID || wire.RequestID != expectedRequestID {
		return classError(ErrorHelper)
	}
	return nil
}

func marshalSessionReadyForTouch(sessionID sessionIdentifier, requestID requestIdentifier) ([]byte, error) {
	encoded, err := json.Marshal(wireSessionReadyForTouch{
		Version: sessionProtocolVersion, Type: sessionReadyForTouchType, SessionID: sessionID, RequestID: requestID,
	})
	return checkedSessionResponse(encoded, err)
}

func unmarshalSessionReadyForTouch(encoded []byte, expectedSessionID sessionIdentifier, expectedRequestID requestIdentifier) error {
	if !validSessionResponseInput(encoded, expectedSessionID, expectedRequestID) {
		return classError(ErrorHelper)
	}
	var wire wireSessionReadyForTouch
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.Version != sessionProtocolVersion ||
		wire.Type != sessionReadyForTouchType || wire.SessionID != expectedSessionID || wire.RequestID != expectedRequestID {
		return classError(ErrorHelper)
	}
	return nil
}

func marshalSessionContinue(
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	continuationID continuationIdentifier,
) ([]byte, error) {
	encoded, err := json.Marshal(wireSessionContinue{
		Version: sessionProtocolVersion, Type: sessionContinueType, SessionID: sessionID, RequestID: requestID,
		ContinuationID: continuationID,
	})
	return checkedSessionResponse(encoded, err)
}

func unmarshalSessionContinue(
	encoded []byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
) (continuationIdentifier, error) {
	if !validSessionResponseInput(encoded, expectedSessionID, expectedRequestID) {
		return continuationIdentifier{}, classError(ErrorHelper)
	}
	var wire wireSessionContinue
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.Version != sessionProtocolVersion ||
		wire.Type != sessionContinueType || wire.SessionID != expectedSessionID || wire.RequestID != expectedRequestID ||
		!identifierIsValid(wire.ContinuationID[:]) {
		return continuationIdentifier{}, classError(ErrorHelper)
	}
	return wire.ContinuationID, nil
}

func marshalSessionEarlyResult(sessionID sessionIdentifier, requestID requestIdentifier, class ErrorClass) ([]byte, error) {
	if !validHardwareSessionErrorClass(class) {
		return nil, classError(ErrorHelper)
	}
	encoded, err := json.Marshal(wireSessionResult{
		Version: sessionProtocolVersion, Type: sessionResultType, SessionID: sessionID, RequestID: requestID, Error: class,
	})
	return checkedSessionResponse(encoded, err)
}

func unmarshalSessionEarlyResult(
	encoded []byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
) error {
	wire, err := unmarshalSessionResultWire(encoded, expectedSessionID, expectedRequestID)
	if err != nil {
		return err
	}
	defer clearWireFileKey(wire.FileKey)
	if wire.ContinuationID != nil || wire.OK || wire.FileKey != nil || !validHardwareSessionErrorClass(wire.Error) {
		return classError(ErrorHelper)
	}
	return classError(wire.Error)
}

func marshalSessionResult(
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	continuationID continuationIdentifier,
	fileKey []byte,
	class ErrorClass,
) ([]byte, error) {
	if !identifierIsValid(continuationID[:]) {
		return nil, classError(ErrorHelper)
	}
	continuationCopy := continuationID
	wire := wireSessionResult{
		Version: sessionProtocolVersion, Type: sessionResultType, SessionID: sessionID, RequestID: requestID,
		ContinuationID: &continuationCopy,
	}
	var encodedKey wireFileKey
	defer clear(encodedKey[:])
	if class != "" {
		if len(fileKey) != 0 {
			return nil, classError(ErrorHelper)
		}
		if !validHardwareSessionErrorClass(class) {
			class = ErrorHelper
		}
		wire.Error = class
	} else {
		if len(fileKey) != fileKeySize {
			return nil, classError(ErrorHelper)
		}
		wire.OK = true
		copy(encodedKey[:], fileKey)
		wire.FileKey = &encodedKey
	}
	encoded, err := json.Marshal(wire)
	return checkedSessionResponse(encoded, err)
}

func unmarshalSessionResult(
	encoded []byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
	expectedContinuationID continuationIdentifier,
) ([]byte, error) {
	if !identifierIsValid(expectedContinuationID[:]) {
		return nil, classError(ErrorHelper)
	}
	wire, err := unmarshalSessionResultWire(encoded, expectedSessionID, expectedRequestID)
	if err != nil {
		return nil, err
	}
	defer clearWireFileKey(wire.FileKey)
	if wire.ContinuationID == nil || *wire.ContinuationID != expectedContinuationID {
		return nil, classError(ErrorHelper)
	}
	if wire.OK {
		if wire.Error != "" || wire.FileKey == nil {
			return nil, classError(ErrorHelper)
		}
		fileKey := make([]byte, fileKeySize)
		copy(fileKey, wire.FileKey[:])
		return fileKey, nil
	}
	if wire.FileKey != nil || !validHardwareSessionErrorClass(wire.Error) {
		return nil, classError(ErrorHelper)
	}
	return nil, classError(wire.Error)
}

func unmarshalSessionResultWire(
	encoded []byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
) (wireSessionResult, error) {
	if !validSessionResponseInput(encoded, expectedSessionID, expectedRequestID) {
		return wireSessionResult{}, classError(ErrorHelper)
	}
	var wire wireSessionResult
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.Version != sessionProtocolVersion ||
		wire.Type != sessionResultType || wire.SessionID != expectedSessionID || wire.RequestID != expectedRequestID {
		clearWireFileKey(wire.FileKey)
		return wireSessionResult{}, classError(ErrorHelper)
	}
	return wire, nil
}

func validHardwareSessionErrorClass(class ErrorClass) bool {
	switch class {
	case ErrorInvalidRequest, ErrorConfiguration, ErrorPINProvider,
		ErrorHardwareMismatch, ErrorHardwarePIN, ErrorHardware, ErrorUnwrap,
		ErrorCanceled, ErrorTimeout, ErrorHelper:
		return true
	default:
		return false
	}
}

func checkedSessionResponse(encoded []byte, err error) ([]byte, error) {
	if err != nil || len(encoded) == 0 || len(encoded) > maxSessionResponseFrame {
		clear(encoded)
		return nil, classError(ErrorHelper)
	}
	return encoded, nil
}

func validSessionResponseInput(encoded []byte, sessionID sessionIdentifier, requestID requestIdentifier) bool {
	return len(encoded) > 0 && len(encoded) <= maxSessionResponseFrame &&
		identifierIsValid(sessionID[:]) && identifierIsValid(requestID[:])
}
