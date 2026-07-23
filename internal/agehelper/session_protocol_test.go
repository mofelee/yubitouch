package agehelper

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSessionIdentifiersAreRandomCanonicalLowercaseHex(t *testing.T) {
	sessionID, err := newSessionIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := newRequestIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	secondSessionID, err := newSessionIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	if !identifierIsValid(sessionID[:]) || !identifierIsValid(requestID[:]) || sessionID == secondSessionID {
		t.Fatal("identifier generation returned a zero or repeated identifier")
	}

	encoded, err := json.Marshal(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	want := `"` + hex.EncodeToString(sessionID[:]) + `"`
	if string(encoded) != want || len(encoded) != encodedIdentifierSize+2 {
		t.Fatalf("identifier = %s, want %s", encoded, want)
	}
	var decoded sessionIdentifier
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != sessionID {
		t.Fatalf("decoded identifier = %x, err = %v", decoded, err)
	}

	for name, value := range map[string]string{
		"zero":      `"00000000000000000000000000000000"`,
		"short":     `"010203"`,
		"uppercase": `"0102030405060708090A0b0c0d0e0f10"`,
		"non-hex":   `"0102030405060708090g0b0c0d0e0f10"`,
		"null":      `null`,
		"array":     `[1,2,3]`,
	} {
		t.Run(name, func(t *testing.T) {
			var identifier sessionIdentifier
			if err := json.Unmarshal([]byte(value), &identifier); err == nil {
				t.Fatal("invalid identifier was accepted")
			}
			if identifier != (sessionIdentifier{}) {
				t.Fatal("failed identifier decoding retained bytes")
			}
		})
	}
	if _, err := json.Marshal(sessionIdentifier{}); err == nil {
		t.Fatal("zero session identifier was encoded")
	}
	if _, err := json.Marshal(requestIdentifier{}); err == nil {
		t.Fatal("zero request identifier was encoded")
	}
	if _, err := json.Marshal(continuationIdentifier{}); err == nil {
		t.Fatal("zero continuation identifier was encoded")
	}
}

func TestSessionProtocolLegalRoundTrip(t *testing.T) {
	fixture := newHelperFixture(t)
	sessionID, requestID := fixedSessionBinding()
	continuationID := fixedContinuationBinding()

	requestPayload, err := marshalSessionRequest(sessionID, requestID, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(requestPayload)
	gotRequestID, request, err := unmarshalSessionRequest(requestPayload, sessionID)
	if err != nil || gotRequestID != requestID || request.Envelope != fixture.hardwareEnvelope {
		t.Fatalf("request round trip = %x, %#v, %v", gotRequestID, request, err)
	}

	ready, err := marshalSessionReady(sessionID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ready)
	if err := unmarshalSessionReady(ready, sessionID, requestID); err != nil {
		t.Fatal(err)
	}

	readyForTouch, err := marshalSessionReadyForTouch(sessionID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(readyForTouch)
	if err := unmarshalSessionReadyForTouch(readyForTouch, sessionID, requestID); err != nil {
		t.Fatal(err)
	}

	continued, err := marshalSessionContinue(sessionID, requestID, continuationID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(continued)
	if got, err := unmarshalSessionContinue(continued, sessionID, requestID); err != nil || got != continuationID {
		t.Fatal(err)
	}

	result, err := marshalSessionResult(sessionID, requestID, continuationID, fixture.fileKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result)
	fileKey, err := unmarshalSessionResult(result, sessionID, requestID, continuationID)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSecret(fileKey)
	if !bytes.Equal(fileKey, fixture.fileKey) {
		t.Fatal("session result changed the file key")
	}

	errorResult, err := marshalSessionResult(sessionID, requestID, continuationID, nil, ErrorHardware)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(errorResult)
	if _, err := unmarshalSessionResult(errorResult, sessionID, requestID, continuationID); ErrorClassOf(err) != ErrorHardware {
		t.Fatalf("error result class = %q", ErrorClassOf(err))
	}
	wrongContinuationID := continuationID
	wrongContinuationID[0] ^= 0xff
	if _, err := unmarshalSessionResult(result, sessionID, requestID, wrongContinuationID); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("result accepted a continuation binding not disclosed by continue")
	}
	earlyResult, err := marshalSessionEarlyResult(sessionID, requestID, ErrorPINProvider)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(earlyResult)
	if err := unmarshalSessionEarlyResult(earlyResult, sessionID, requestID); ErrorClassOf(err) != ErrorPINProvider {
		t.Fatalf("early result class = %q", ErrorClassOf(err))
	}
}

func TestSessionProtocolParsersRejectWrongTypesAndBindings(t *testing.T) {
	fixture := newHelperFixture(t)
	sessionID, requestID := fixedSessionBinding()
	continuationID := fixedContinuationBinding()
	wrongSessionID, wrongRequestID := differentSessionBinding()

	payloads := make(map[string][]byte)
	var err error
	payloads[sessionRequestType], err = marshalSessionRequest(sessionID, requestID, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	payloads[sessionReadyType], err = marshalSessionReady(sessionID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	payloads[sessionReadyForTouchType], err = marshalSessionReadyForTouch(sessionID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	payloads[sessionContinueType], err = marshalSessionContinue(sessionID, requestID, continuationID)
	if err != nil {
		t.Fatal(err)
	}
	payloads[sessionResultType], err = marshalSessionResult(sessionID, requestID, continuationID, fixture.fileKey, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range payloads {
		defer clear(payload)
	}

	parsers := map[string]func([]byte) error{
		sessionRequestType: func(payload []byte) error {
			gotRequestID, _, err := unmarshalSessionRequest(payload, sessionID)
			if err == nil && gotRequestID != requestID {
				return classError(ErrorHelper)
			}
			return err
		},
		sessionReadyType: func(payload []byte) error {
			return unmarshalSessionReady(payload, sessionID, requestID)
		},
		sessionReadyForTouchType: func(payload []byte) error {
			return unmarshalSessionReadyForTouch(payload, sessionID, requestID)
		},
		sessionContinueType: func(payload []byte) error {
			_, err := unmarshalSessionContinue(payload, sessionID, requestID)
			return err
		},
		sessionResultType: func(payload []byte) error {
			key, err := unmarshalSessionResult(payload, sessionID, requestID, continuationID)
			ClearSecret(key)
			return err
		},
	}
	for payloadType, payload := range payloads {
		for parserType, parse := range parsers {
			err := parse(payload)
			if parserType == payloadType && err != nil {
				t.Fatalf("%s parser rejected %s: %v", parserType, payloadType, err)
			}
			if parserType != payloadType && err == nil {
				t.Fatalf("%s parser accepted %s", parserType, payloadType)
			}
		}
	}

	if _, _, err := unmarshalSessionRequest(payloads[sessionRequestType], wrongSessionID); err == nil {
		t.Fatal("request parser accepted the wrong session identifier")
	}
	for name, parse := range map[string]func() error{
		"ready session": func() error { return unmarshalSessionReady(payloads[sessionReadyType], wrongSessionID, requestID) },
		"ready request": func() error { return unmarshalSessionReady(payloads[sessionReadyType], sessionID, wrongRequestID) },
		"touch session": func() error {
			return unmarshalSessionReadyForTouch(payloads[sessionReadyForTouchType], wrongSessionID, requestID)
		},
		"touch request": func() error {
			return unmarshalSessionReadyForTouch(payloads[sessionReadyForTouchType], sessionID, wrongRequestID)
		},
		"continue session": func() error {
			_, err := unmarshalSessionContinue(payloads[sessionContinueType], wrongSessionID, requestID)
			return err
		},
		"continue request": func() error {
			_, err := unmarshalSessionContinue(payloads[sessionContinueType], sessionID, wrongRequestID)
			return err
		},
		"result session": func() error {
			key, err := unmarshalSessionResult(payloads[sessionResultType], wrongSessionID, requestID, continuationID)
			ClearSecret(key)
			return err
		},
		"result request": func() error {
			key, err := unmarshalSessionResult(payloads[sessionResultType], sessionID, wrongRequestID, continuationID)
			ClearSecret(key)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := parse(); err == nil {
				t.Fatal("wrong binding was accepted")
			}
		})
	}
}

func TestSessionProtocolRejectsNonCanonicalMalformedAndOversizedMessages(t *testing.T) {
	fixture := newHelperFixture(t)
	sessionID, requestID := fixedSessionBinding()
	ready, err := marshalSessionReady(sessionID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ready)
	sessionHex := hex.EncodeToString(sessionID[:])
	requestHex := hex.EncodeToString(requestID[:])

	mutations := map[string][]byte{
		"empty":         nil,
		"malformed":     []byte(`{"version":2`),
		"leading space": append([]byte{' '}, ready...),
		"trailing byte": append(append([]byte(nil), ready...), '\n'),
		"field reorder": []byte(fmt.Sprintf(`{"type":"session_ready","version":2,"session_id":"%s","request_id":"%s"}`, sessionHex, requestHex)),
		"duplicate":     bytes.Replace(ready, []byte(`"type":"session_ready"`), []byte(`"type":"session_ready","type":"session_ready"`), 1),
		"unknown":       bytes.Replace(ready, []byte(`"type":"session_ready"`), []byte(`"type":"session_ready","unknown":true`), 1),
		"wrong version": bytes.Replace(ready, []byte(`"version":2`), []byte(`"version":1`), 1),
		"uppercase id":  bytes.Replace(ready, []byte(sessionHex), []byte(strings.ToUpper(sessionHex)), 1),
		"short id":      bytes.Replace(ready, []byte(sessionHex), []byte(sessionHex[:30]), 1),
		"zero id":       bytes.Replace(ready, []byte(sessionHex), []byte(strings.Repeat("0", encodedIdentifierSize)), 1),
		"oversized":     bytes.Repeat([]byte{'x'}, maxSessionResponseFrame+1),
	}
	for name, payload := range mutations {
		t.Run(name, func(t *testing.T) {
			defer clear(payload)
			if err := unmarshalSessionReady(payload, sessionID, requestID); ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}

	request, err := marshalSessionRequest(sessionID, requestID, Request{Envelope: fixture.hardwareEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(request)
	for name, payload := range map[string][]byte{
		"outer unknown":    bytes.Replace(request, []byte(`"envelope":`), []byte(`"unknown":1,"envelope":`), 1),
		"outer duplicate":  bytes.Replace(request, []byte(`"request_id":`), []byte(`"request_id":"`+requestHex+`","request_id":`), 1),
		"envelope unknown": bytes.Replace(request, []byte(`"envelope":{`), []byte(`"envelope":{"unknown":1,`), 1),
		"oversized":        bytes.Repeat([]byte{'x'}, maxSessionRequestFrame+1),
	} {
		t.Run("request "+name, func(t *testing.T) {
			defer clear(payload)
			if _, _, err := unmarshalSessionRequest(payload, sessionID); ErrorClassOf(err) != ErrorInvalidRequest {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}
	if _, err := marshalSessionRequest(sessionID, requestID, Request{Envelope: fixture.recoveryEnvelope}); ErrorClassOf(err) != ErrorInvalidRequest {
		t.Fatal("recovery envelope was accepted by the hardware session protocol")
	}
	if _, err := marshalSessionReady(sessionIdentifier{}, requestID); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("zero session identifier was encoded")
	}
}

func TestSessionResultRequiresExclusiveExactFileKeyOrFixedError(t *testing.T) {
	sessionID, requestID := fixedSessionBinding()
	continuationID := fixedContinuationBinding()
	sessionHex := hex.EncodeToString(sessionID[:])
	requestHex := hex.EncodeToString(requestID[:])
	continuationHex := hex.EncodeToString(continuationID[:])
	prefix := fmt.Sprintf(`{"version":2,"type":"result","session_id":"%s","request_id":"%s","continuation_id":"%s",`, sessionHex, requestHex, continuationHex)
	validKey := `[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]`

	invalid := map[string]string{
		"success missing key": prefix + `"ok":true}`,
		"success null key":    prefix + `"ok":true,"file_key":null}`,
		"success short key":   prefix + `"ok":true,"file_key":[0,1,2]}`,
		"success long key":    prefix + `"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}`,
		"success range":       prefix + `"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,256]}`,
		"success with error":  prefix + `"ok":true,"file_key":` + validKey + `,"error":"hardware_failed"}`,
		"failure missing":     prefix + `"ok":false}`,
		"failure unknown":     prefix + `"ok":false,"error":"private"}`,
		"failure recovery":    prefix + `"ok":false,"error":"recovery_unavailable"}`,
		"failure with key":    prefix + `"ok":false,"file_key":` + validKey + `,"error":"hardware_failed"}`,
		"failure null key":    prefix + `"ok":false,"file_key":null,"error":"hardware_failed"}`,
	}
	for name, payload := range invalid {
		t.Run(name, func(t *testing.T) {
			encoded := []byte(payload)
			defer clear(encoded)
			key, err := unmarshalSessionResult(encoded, sessionID, requestID, continuationID)
			ClearSecret(key)
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}

	if _, err := marshalSessionResult(sessionID, requestID, continuationID, []byte("short"), ""); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("short file key was encoded")
	}
	if _, err := marshalSessionResult(sessionID, requestID, continuationID, []byte("0123456789abcdef"), ErrorHardware); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("mixed file key and error were encoded")
	}
	payload, err := marshalSessionResult(sessionID, requestID, continuationID, nil, ErrorClass("private"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if _, err := unmarshalSessionResult(payload, sessionID, requestID, continuationID); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("unknown result error did not collapse to helper_failed")
	}
	for _, class := range []ErrorClass{ErrorRecoveryUnavailable, ErrorRecoveryMismatch} {
		payload, err := marshalSessionResult(sessionID, requestID, continuationID, nil, class)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unmarshalSessionResult(payload, sessionID, requestID, continuationID); ErrorClassOf(err) != ErrorHelper {
			clear(payload)
			t.Fatalf("recovery class %q crossed the hardware session protocol", class)
		}
		clear(payload)
	}
}

func TestSessionFramesSupportPersistentSequentialExchange(t *testing.T) {
	sessionID, requestID := fixedSessionBinding()
	ready, err := marshalSessionReady(sessionID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ready)
	touch, err := marshalSessionReadyForTouch(sessionID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(touch)

	var stream bytes.Buffer
	if err := writeFrame(&stream, ready, maxSessionResponseFrame); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&stream, touch, maxSessionResponseFrame); err != nil {
		t.Fatal(err)
	}
	first, err := readFrame(&stream, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)
	second, err := readFrame(&stream, maxSessionResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second)
	if err := unmarshalSessionReady(first, sessionID, requestID); err != nil {
		t.Fatal(err)
	}
	if err := unmarshalSessionReadyForTouch(second, sessionID, requestID); err != nil {
		t.Fatal(err)
	}
	if err := ensureEOF(&stream); err != nil {
		t.Fatal(err)
	}
}

func fixedSessionBinding() (sessionIdentifier, requestIdentifier) {
	var sessionID sessionIdentifier
	var requestID requestIdentifier
	for index := 0; index < identifierSize; index++ {
		sessionID[index] = byte(index + 1)
		requestID[index] = byte(index + 33)
	}
	return sessionID, requestID
}

func differentSessionBinding() (sessionIdentifier, requestIdentifier) {
	var sessionID sessionIdentifier
	var requestID requestIdentifier
	for index := 0; index < identifierSize; index++ {
		sessionID[index] = byte(index + 65)
		requestID[index] = byte(index + 97)
	}
	return sessionID, requestID
}

func fixedContinuationBinding() continuationIdentifier {
	var continuationID continuationIdentifier
	for index := range continuationID {
		continuationID[index] = byte(index + 129)
	}
	return continuationID
}
