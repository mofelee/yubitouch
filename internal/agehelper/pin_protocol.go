package agehelper

import (
	"encoding/binary"
	"io"
)

const (
	pinResolverProtocolMagic   uint32 = 0x5954504e // YTPN
	pinResolverProtocolVersion byte   = 2
	pinResolverRequestType     byte   = 1
	pinResolverResponseType    byte   = 2

	pinResolverStatusSuccess byte = 0
	pinResolverStatusError   byte = 1

	maxPINLength = 64
)

const (
	pinResolverMagicOffset     = 0
	pinResolverVersionOffset   = pinResolverMagicOffset + 4
	pinResolverTypeOffset      = pinResolverVersionOffset + 1
	pinResolverSessionIDOffset = pinResolverTypeOffset + 1
	pinResolverRequestIDOffset = pinResolverSessionIDOffset + identifierSize
	pinResolverBindingOffset   = pinResolverRequestIDOffset + identifierSize
	pinResolverRequestSize     = pinResolverBindingOffset + configSnapshotBindingSize

	pinResolverStatusOffset       = pinResolverRequestSize
	pinResolverLengthOffset       = pinResolverStatusOffset + 1
	pinResolverResponseHeaderSize = pinResolverLengthOffset + 2
	maxPINResolverFrame           = pinResolverResponseHeaderSize + maxPINLength
)

const (
	pinResolverErrorConfiguration byte = 1
	pinResolverErrorProvider      byte = 2
	pinResolverErrorCanceled      byte = 3
	pinResolverErrorTimeout       byte = 4
	pinResolverErrorHelper        byte = 5
)

func marshalPINResolverRequest(
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	binding configSnapshotBinding,
) ([]byte, error) {
	if !identifierIsValid(sessionID[:]) || !identifierIsValid(requestID[:]) || !validConfigSnapshotBinding(binding) {
		return nil, classError(ErrorInvalidRequest)
	}
	payload := make([]byte, pinResolverRequestSize)
	putPINResolverHeader(payload, pinResolverRequestType, sessionID, requestID, binding)
	return payload, nil
}

func unmarshalPINResolverRequest(
	payload []byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
) (configSnapshotBinding, error) {
	if len(payload) != pinResolverRequestSize ||
		!validPINResolverBaseHeader(payload, pinResolverRequestType, expectedSessionID, expectedRequestID) {
		return configSnapshotBinding{}, classError(ErrorInvalidRequest)
	}
	var binding configSnapshotBinding
	copy(binding[:], payload[pinResolverBindingOffset:pinResolverRequestSize])
	if !validConfigSnapshotBinding(binding) {
		return configSnapshotBinding{}, classError(ErrorInvalidRequest)
	}
	return binding, nil
}

func writePINResolverRequestFrame(
	writer io.Writer,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	binding configSnapshotBinding,
) error {
	if writer == nil {
		return classError(ErrorHelper)
	}
	payload, err := marshalPINResolverRequest(sessionID, requestID, binding)
	if err != nil {
		return err
	}
	defer clear(payload)
	if err := writeFrame(writer, payload, maxPINResolverFrame); err != nil {
		return classError(ErrorHelper)
	}
	return nil
}

func readPINResolverRequestFrame(
	reader io.Reader,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
) (configSnapshotBinding, error) {
	if reader == nil {
		return configSnapshotBinding{}, classError(ErrorInvalidRequest)
	}
	payload, err := readFrame(reader, maxPINResolverFrame)
	if err != nil {
		return configSnapshotBinding{}, classError(ErrorInvalidRequest)
	}
	defer clear(payload)
	if ensureEOF(reader) != nil {
		return configSnapshotBinding{}, classError(ErrorInvalidRequest)
	}
	return unmarshalPINResolverRequest(payload, expectedSessionID, expectedRequestID)
}

func marshalPINResolverResponse(
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	binding configSnapshotBinding,
	pin []byte,
	class ErrorClass,
) ([]byte, error) {
	if !identifierIsValid(sessionID[:]) || !identifierIsValid(requestID[:]) || !validConfigSnapshotBinding(binding) {
		return nil, classError(ErrorHelper)
	}
	status := pinResolverStatusSuccess
	dataLength := len(pin)
	var errorCode byte
	if class == "" {
		if dataLength == 0 || dataLength > maxPINLength {
			return nil, classError(ErrorHelper)
		}
	} else {
		if dataLength != 0 {
			return nil, classError(ErrorHelper)
		}
		var ok bool
		errorCode, ok = pinResolverErrorClassCode(class)
		if !ok {
			return nil, classError(ErrorHelper)
		}
		status = pinResolverStatusError
		dataLength = 1
	}

	payload := make([]byte, pinResolverResponseHeaderSize+dataLength)
	putPINResolverHeader(payload, pinResolverResponseType, sessionID, requestID, binding)
	payload[pinResolverStatusOffset] = status
	binary.BigEndian.PutUint16(payload[pinResolverLengthOffset:pinResolverResponseHeaderSize], uint16(dataLength))
	if status == pinResolverStatusSuccess {
		copy(payload[pinResolverResponseHeaderSize:], pin)
	} else {
		payload[pinResolverResponseHeaderSize] = errorCode
	}
	return payload, nil
}

// unmarshalPINResolverResponse consumes and clears payload on every path. A
// successful caller owns the returned mutable PIN and must clear it after use.
func unmarshalPINResolverResponse(
	payload []byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
	expectedBinding configSnapshotBinding,
) ([]byte, error) {
	defer clear(payload)
	if len(payload) < pinResolverResponseHeaderSize || len(payload) > maxPINResolverFrame ||
		!validPINResolverHeader(payload, pinResolverResponseType, expectedSessionID, expectedRequestID, expectedBinding) {
		return nil, classError(ErrorHelper)
	}
	declaredLength := int(binary.BigEndian.Uint16(payload[pinResolverLengthOffset:pinResolverResponseHeaderSize]))
	if declaredLength != len(payload)-pinResolverResponseHeaderSize {
		return nil, classError(ErrorHelper)
	}
	switch payload[pinResolverStatusOffset] {
	case pinResolverStatusSuccess:
		if declaredLength == 0 || declaredLength > maxPINLength {
			return nil, classError(ErrorHelper)
		}
		pin := make([]byte, declaredLength)
		copy(pin, payload[pinResolverResponseHeaderSize:])
		return pin, nil
	case pinResolverStatusError:
		if declaredLength != 1 {
			return nil, classError(ErrorHelper)
		}
		class, ok := pinResolverErrorCodeClass(payload[pinResolverResponseHeaderSize])
		if !ok {
			return nil, classError(ErrorHelper)
		}
		return nil, classError(class)
	default:
		return nil, classError(ErrorHelper)
	}
}

func writePINResolverResponseFrame(
	writer io.Writer,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	binding configSnapshotBinding,
	pin []byte,
	class ErrorClass,
) error {
	if writer == nil {
		return classError(ErrorHelper)
	}
	payload, err := marshalPINResolverResponse(sessionID, requestID, binding, pin, class)
	if err != nil {
		return err
	}
	defer clear(payload)
	if err := writeFrame(writer, payload, maxPINResolverFrame); err != nil {
		return classError(ErrorHelper)
	}
	return nil
}

func readPINResolverResponseFrame(
	reader io.Reader,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
	expectedBinding configSnapshotBinding,
) ([]byte, error) {
	if reader == nil {
		return nil, classError(ErrorHelper)
	}
	payload, err := readFrame(reader, maxPINResolverFrame)
	if err != nil {
		return nil, classError(ErrorHelper)
	}
	if ensureEOF(reader) != nil {
		clear(payload)
		return nil, classError(ErrorHelper)
	}
	return unmarshalPINResolverResponse(payload, expectedSessionID, expectedRequestID, expectedBinding)
}

func putPINResolverHeader(
	payload []byte,
	messageType byte,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	binding configSnapshotBinding,
) {
	binary.BigEndian.PutUint32(payload[pinResolverMagicOffset:pinResolverVersionOffset], pinResolverProtocolMagic)
	payload[pinResolverVersionOffset] = pinResolverProtocolVersion
	payload[pinResolverTypeOffset] = messageType
	copy(payload[pinResolverSessionIDOffset:pinResolverRequestIDOffset], sessionID[:])
	copy(payload[pinResolverRequestIDOffset:pinResolverBindingOffset], requestID[:])
	copy(payload[pinResolverBindingOffset:pinResolverRequestSize], binding[:])
}

func validPINResolverHeader(
	payload []byte,
	messageType byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
	expectedBinding configSnapshotBinding,
) bool {
	if !validConfigSnapshotBinding(expectedBinding) ||
		!validPINResolverBaseHeader(payload, messageType, expectedSessionID, expectedRequestID) {
		return false
	}
	var binding configSnapshotBinding
	copy(binding[:], payload[pinResolverBindingOffset:pinResolverRequestSize])
	return binding == expectedBinding
}

func validPINResolverBaseHeader(
	payload []byte,
	messageType byte,
	expectedSessionID sessionIdentifier,
	expectedRequestID requestIdentifier,
) bool {
	if len(payload) < pinResolverRequestSize || !identifierIsValid(expectedSessionID[:]) ||
		!identifierIsValid(expectedRequestID[:]) ||
		binary.BigEndian.Uint32(payload[pinResolverMagicOffset:pinResolverVersionOffset]) != pinResolverProtocolMagic ||
		payload[pinResolverVersionOffset] != pinResolverProtocolVersion || payload[pinResolverTypeOffset] != messageType {
		return false
	}
	var sessionID sessionIdentifier
	var requestID requestIdentifier
	copy(sessionID[:], payload[pinResolverSessionIDOffset:pinResolverRequestIDOffset])
	copy(requestID[:], payload[pinResolverRequestIDOffset:pinResolverBindingOffset])
	return sessionID == expectedSessionID && requestID == expectedRequestID
}

func pinResolverErrorClassCode(class ErrorClass) (byte, bool) {
	switch class {
	case ErrorConfiguration:
		return pinResolverErrorConfiguration, true
	case ErrorPINProvider:
		return pinResolverErrorProvider, true
	case ErrorCanceled:
		return pinResolverErrorCanceled, true
	case ErrorTimeout:
		return pinResolverErrorTimeout, true
	case ErrorHelper:
		return pinResolverErrorHelper, true
	default:
		return 0, false
	}
}

func pinResolverErrorCodeClass(code byte) (ErrorClass, bool) {
	switch code {
	case pinResolverErrorConfiguration:
		return ErrorConfiguration, true
	case pinResolverErrorProvider:
		return ErrorPINProvider, true
	case pinResolverErrorCanceled:
		return ErrorCanceled, true
	case pinResolverErrorTimeout:
		return ErrorTimeout, true
	case pinResolverErrorHelper:
		return ErrorHelper, true
	default:
		return "", false
	}
}
