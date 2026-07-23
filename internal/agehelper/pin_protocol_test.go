package agehelper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestPINResolverRequestBinaryRoundTripAndBinding(t *testing.T) {
	sessionID, requestID := fixedSessionBinding()
	binding := fixedConfigSnapshotBinding()
	payload, err := marshalPINResolverRequest(sessionID, requestID, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if len(payload) != pinResolverRequestSize || binary.BigEndian.Uint32(payload[:4]) != pinResolverProtocolMagic {
		t.Fatalf("request payload length/magic = %d/%x", len(payload), payload[:4])
	}
	if got, err := unmarshalPINResolverRequest(payload, sessionID, requestID); err != nil || got != binding {
		t.Fatalf("binding=%x err=%v", got, err)
	}

	wrongSessionID, wrongRequestID := differentSessionBinding()
	for name, test := range map[string]struct {
		payload   []byte
		sessionID sessionIdentifier
		requestID requestIdentifier
	}{
		"empty":         {nil, sessionID, requestID},
		"short":         {append([]byte(nil), payload[:len(payload)-1]...), sessionID, requestID},
		"trailing":      {append(append([]byte(nil), payload...), 0), sessionID, requestID},
		"wrong session": {append([]byte(nil), payload...), wrongSessionID, requestID},
		"wrong request": {append([]byte(nil), payload...), sessionID, wrongRequestID},
		"zero session":  {append([]byte(nil), payload...), sessionIdentifier{}, requestID},
		"zero request":  {append([]byte(nil), payload...), sessionID, requestIdentifier{}},
	} {
		t.Run(name, func(t *testing.T) {
			defer clear(test.payload)
			if _, err := unmarshalPINResolverRequest(test.payload, test.sessionID, test.requestID); ErrorClassOf(err) != ErrorInvalidRequest {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}
	for name, offset := range map[string]int{
		"magic":   pinResolverMagicOffset,
		"version": pinResolverVersionOffset,
		"type":    pinResolverTypeOffset,
		"session": pinResolverSessionIDOffset,
		"request": pinResolverRequestIDOffset,
	} {
		t.Run(name, func(t *testing.T) {
			mutation := append([]byte(nil), payload...)
			defer clear(mutation)
			mutation[offset] ^= 0xff
			if _, err := unmarshalPINResolverRequest(mutation, sessionID, requestID); ErrorClassOf(err) != ErrorInvalidRequest {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}
	zeroBinding := append([]byte(nil), payload...)
	clear(zeroBinding[pinResolverBindingOffset:pinResolverRequestSize])
	if _, err := unmarshalPINResolverRequest(zeroBinding, sessionID, requestID); ErrorClassOf(err) != ErrorInvalidRequest {
		clear(zeroBinding)
		t.Fatal("zero snapshot binding was accepted")
	}
	clear(zeroBinding)
	if _, err := marshalPINResolverRequest(sessionIdentifier{}, requestID, binding); ErrorClassOf(err) != ErrorInvalidRequest {
		t.Fatal("zero session identifier was encoded")
	}
	if _, err := marshalPINResolverRequest(sessionID, requestID, configSnapshotBinding{}); ErrorClassOf(err) != ErrorInvalidRequest {
		t.Fatal("zero snapshot binding was encoded")
	}
}

func TestPINResolverSuccessResponseIsBinaryMutableAndConsumed(t *testing.T) {
	sessionID, requestID := fixedSessionBinding()
	binding := fixedConfigSnapshotBinding()
	for name, pin := range map[string][]byte{
		"one byte": {0},
		"binary":   {0, 0xff, 0x80, '1', '\n', 0},
		"maximum":  bytes.Repeat([]byte{0xa5}, maxPINLength),
	} {
		t.Run(name, func(t *testing.T) {
			original := append([]byte(nil), pin...)
			defer clear(original)
			payload, err := marshalPINResolverResponse(sessionID, requestID, binding, pin, "")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pin, original) {
				t.Fatal("marshaling changed the caller's PIN")
			}
			if payload[pinResolverStatusOffset] != pinResolverStatusSuccess ||
				!bytes.Equal(payload[pinResolverResponseHeaderSize:], pin) {
				t.Fatal("success response did not contain the exact binary PIN")
			}
			decoded, err := unmarshalPINResolverResponse(payload, sessionID, requestID, binding)
			if err != nil {
				t.Fatal(err)
			}
			if !allBytesZero(payload) {
				t.Fatal("consumed response payload retained PIN bytes")
			}
			if !bytes.Equal(decoded, original) {
				t.Fatal("decoded PIN changed")
			}
			ClearSecret(decoded)
			if !allBytesZero(decoded) {
				t.Fatal("decoded PIN was not mutable and clearable")
			}
		})
	}
}

func TestPINResolverFixedErrorResponses(t *testing.T) {
	sessionID, requestID := fixedSessionBinding()
	binding := fixedConfigSnapshotBinding()
	for _, want := range []ErrorClass{
		ErrorConfiguration,
		ErrorPINProvider,
		ErrorCanceled,
		ErrorTimeout,
		ErrorHelper,
	} {
		t.Run(string(want), func(t *testing.T) {
			payload, err := marshalPINResolverResponse(sessionID, requestID, binding, nil, want)
			if err != nil {
				t.Fatal(err)
			}
			if payload[pinResolverStatusOffset] != pinResolverStatusError || len(payload) != pinResolverResponseHeaderSize+1 {
				t.Fatal("error response did not use the fixed binary status/code layout")
			}
			pin, err := unmarshalPINResolverResponse(payload, sessionID, requestID, binding)
			ClearSecret(pin)
			if ErrorClassOf(err) != want {
				t.Fatalf("error class = %q, want %q", ErrorClassOf(err), want)
			}
			if !allBytesZero(payload) {
				t.Fatal("consumed error payload was not cleared")
			}
		})
	}
}

func TestPINResolverResponseRejectsInvalidLengthsStatusAndBindings(t *testing.T) {
	sessionID, requestID := fixedSessionBinding()
	binding := fixedConfigSnapshotBinding()
	wrongSessionID, wrongRequestID := differentSessionBinding()
	wrongBinding := binding
	wrongBinding[0] ^= 0xff

	for name, test := range map[string]struct {
		pin   []byte
		class ErrorClass
	}{
		"empty success":  {nil, ""},
		"oversize":       {bytes.Repeat([]byte{1}, maxPINLength+1), ""},
		"mixed response": {[]byte("123456"), ErrorPINProvider},
		"wrong error":    {nil, ErrorHardware},
	} {
		t.Run("marshal "+name, func(t *testing.T) {
			defer clear(test.pin)
			payload, err := marshalPINResolverResponse(sessionID, requestID, binding, test.pin, test.class)
			clear(payload)
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}
	if payload, err := marshalPINResolverResponse(sessionIdentifier{}, requestID, binding, []byte{1}, ""); ErrorClassOf(err) != ErrorHelper {
		clear(payload)
		t.Fatal("zero session identifier was encoded")
	}

	valid, err := marshalPINResolverResponse(sessionID, requestID, binding, []byte{0, 1, 2, 3}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(valid)
	errorPayload, err := marshalPINResolverResponse(sessionID, requestID, binding, nil, ErrorPINProvider)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(errorPayload)

	type invalidResponse struct {
		payload   []byte
		sessionID sessionIdentifier
		requestID requestIdentifier
		binding   configSnapshotBinding
	}
	tests := map[string]invalidResponse{
		"empty":             {nil, sessionID, requestID, binding},
		"short header":      {append([]byte(nil), valid[:pinResolverResponseHeaderSize-1]...), sessionID, requestID, binding},
		"truncated data":    {append([]byte(nil), valid[:len(valid)-1]...), sessionID, requestID, binding},
		"trailing data":     {append(append([]byte(nil), valid...), 0), sessionID, requestID, binding},
		"wrong session":     {append([]byte(nil), valid...), wrongSessionID, requestID, binding},
		"wrong request":     {append([]byte(nil), valid...), sessionID, wrongRequestID, binding},
		"wrong binding":     {append([]byte(nil), valid...), sessionID, requestID, wrongBinding},
		"zero session":      {append([]byte(nil), valid...), sessionIdentifier{}, requestID, binding},
		"zero request":      {append([]byte(nil), valid...), sessionID, requestIdentifier{}, binding},
		"zero binding":      {append([]byte(nil), valid...), sessionID, requestID, configSnapshotBinding{}},
		"request as result": {mustPINRequestPayload(t, sessionID, requestID, binding), sessionID, requestID, binding},
	}

	wrongStatus := append([]byte(nil), valid...)
	wrongStatus[pinResolverStatusOffset] = 0x7f
	tests["unknown status"] = invalidResponse{wrongStatus, sessionID, requestID, binding}

	zeroLength := append([]byte(nil), valid[:pinResolverResponseHeaderSize]...)
	binary.BigEndian.PutUint16(zeroLength[pinResolverLengthOffset:pinResolverResponseHeaderSize], 0)
	tests["zero success length"] = invalidResponse{zeroLength, sessionID, requestID, binding}

	unknownCode := append([]byte(nil), errorPayload...)
	unknownCode[pinResolverResponseHeaderSize] = 0xff
	tests["unknown error code"] = invalidResponse{unknownCode, sessionID, requestID, binding}

	errorLength := append(append([]byte(nil), errorPayload...), 0)
	binary.BigEndian.PutUint16(errorLength[pinResolverLengthOffset:pinResolverResponseHeaderSize], 2)
	tests["error length two"] = invalidResponse{errorLength, sessionID, requestID, binding}

	tooLong := make([]byte, pinResolverResponseHeaderSize+maxPINLength+1)
	putPINResolverHeader(tooLong, pinResolverResponseType, sessionID, requestID, binding)
	tooLong[pinResolverStatusOffset] = pinResolverStatusSuccess
	binary.BigEndian.PutUint16(tooLong[pinResolverLengthOffset:pinResolverResponseHeaderSize], maxPINLength+1)
	tests["declared oversize"] = invalidResponse{tooLong, sessionID, requestID, binding}

	for name, offset := range map[string]int{
		"magic":   pinResolverMagicOffset,
		"version": pinResolverVersionOffset,
		"type":    pinResolverTypeOffset,
		"session": pinResolverSessionIDOffset,
		"request": pinResolverRequestIDOffset,
	} {
		mutation := append([]byte(nil), valid...)
		mutation[offset] ^= 0xff
		tests["corrupt "+name] = invalidResponse{mutation, sessionID, requestID, binding}
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pin, err := unmarshalPINResolverResponse(test.payload, test.sessionID, test.requestID, test.binding)
			ClearSecret(pin)
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
			if !allBytesZero(test.payload) {
				t.Fatal("failed response parsing retained payload bytes")
			}
		})
	}
}

func TestPINResolverFramedIORequiresExactlyOneFrameAndEOF(t *testing.T) {
	sessionID, requestID := fixedSessionBinding()
	binding := fixedConfigSnapshotBinding()
	pin := []byte{0, 1, 2, 0xff, '1', '2'}
	originalPIN := append([]byte(nil), pin...)
	defer clear(pin)
	defer clear(originalPIN)

	var requestStream bytes.Buffer
	if err := writePINResolverRequestFrame(&requestStream, sessionID, requestID, binding); err != nil {
		t.Fatal(err)
	}
	requestBytes := append([]byte(nil), requestStream.Bytes()...)
	defer clear(requestBytes)
	if got, err := readPINResolverRequestFrame(bytes.NewReader(requestBytes), sessionID, requestID); err != nil || got != binding {
		t.Fatalf("binding=%x err=%v", got, err)
	}
	for name, stream := range map[string][]byte{
		"trailing":  append(append([]byte(nil), requestBytes...), 0),
		"duplicate": append(append([]byte(nil), requestBytes...), requestBytes...),
		"truncated": append([]byte(nil), requestBytes[:len(requestBytes)-1]...),
	} {
		t.Run("request "+name, func(t *testing.T) {
			defer clear(stream)
			if _, err := readPINResolverRequestFrame(bytes.NewReader(stream), sessionID, requestID); ErrorClassOf(err) != ErrorInvalidRequest {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}

	var responseStream bytes.Buffer
	if err := writePINResolverResponseFrame(&responseStream, sessionID, requestID, binding, pin, ""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pin, originalPIN) {
		t.Fatal("framed response write changed the caller's PIN")
	}
	responseBytes := append([]byte(nil), responseStream.Bytes()...)
	defer clear(responseBytes)
	decoded, err := readPINResolverResponseFrame(bytes.NewReader(responseBytes), sessionID, requestID, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, pin) {
		t.Fatal("framed response changed the PIN")
	}
	ClearSecret(decoded)

	for name, stream := range map[string][]byte{
		"trailing":  append(append([]byte(nil), responseBytes...), 0),
		"duplicate": append(append([]byte(nil), responseBytes...), responseBytes...),
		"truncated": append([]byte(nil), responseBytes[:len(responseBytes)-1]...),
	} {
		t.Run("response "+name, func(t *testing.T) {
			defer clear(stream)
			decoded, err := readPINResolverResponseFrame(bytes.NewReader(stream), sessionID, requestID, binding)
			ClearSecret(decoded)
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}

	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxPINResolverFrame+1)
	oversized.Write(header[:])
	if decoded, err := readPINResolverResponseFrame(&oversized, sessionID, requestID, binding); ErrorClassOf(err) != ErrorHelper {
		ClearSecret(decoded)
		t.Fatalf("oversized error class = %q", ErrorClassOf(err))
	}

	if err := writePINResolverRequestFrame(nil, sessionID, requestID, binding); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("nil request writer was accepted")
	}
	if _, err := readPINResolverRequestFrame(nil, sessionID, requestID); ErrorClassOf(err) != ErrorInvalidRequest {
		t.Fatal("nil request reader was accepted")
	}
	if err := writePINResolverResponseFrame(nil, sessionID, requestID, binding, pin, ""); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("nil response writer was accepted")
	}
	if decoded, err := readPINResolverResponseFrame(nil, sessionID, requestID, binding); ErrorClassOf(err) != ErrorHelper {
		ClearSecret(decoded)
		t.Fatal("nil response reader was accepted")
	}
	if err := writePINResolverResponseFrame(noProgressPINWriter{}, sessionID, requestID, binding, pin, ""); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("writer making no progress was accepted")
	}
	if err := writePINResolverResponseFrame(failingPINWriter{}, sessionID, requestID, binding, pin, ""); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("failing writer was accepted")
	}
}

func mustPINRequestPayload(
	t *testing.T,
	sessionID sessionIdentifier,
	requestID requestIdentifier,
	binding configSnapshotBinding,
) []byte {
	t.Helper()
	payload, err := marshalPINResolverRequest(sessionID, requestID, binding)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func fixedConfigSnapshotBinding() configSnapshotBinding {
	var binding configSnapshotBinding
	for index := range binding {
		binding[index] = byte(index + 65)
	}
	return binding
}

func allBytesZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

type noProgressPINWriter struct{}

func (noProgressPINWriter) Write([]byte) (int, error) { return 0, nil }

type failingPINWriter struct{}

func (failingPINWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

var _ io.Writer = noProgressPINWriter{}
var _ io.Writer = failingPINWriter{}
