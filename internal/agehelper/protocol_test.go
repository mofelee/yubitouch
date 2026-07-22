package agehelper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestProtocolRoundTripAndStrictJSON(t *testing.T) {
	fixture := newHelperFixture(t)
	encoded, err := marshalRequest(Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	if err != nil {
		t.Fatal(err)
	}
	request, err := unmarshalRequest(encoded, ModeHardware)
	if err != nil {
		t.Fatal(err)
	}
	if request.Envelope != fixture.hardwareEnvelope {
		t.Fatal("request envelope changed during wire round trip")
	}

	mutations := [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		bytes.Replace(encoded, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
		bytes.Replace(encoded, []byte(`"version":2`), []byte(`"unknown":1,"version":2`), 1),
	}
	for _, mutation := range mutations {
		if _, err := unmarshalRequest(mutation, ModeHardware); ErrorClassOf(err) != ErrorInvalidRequest {
			t.Fatalf("mutation error class = %q, want %q", ErrorClassOf(err), ErrorInvalidRequest)
		}
	}
	if _, err := unmarshalRequest(encoded, ModeRecovery); ErrorClassOf(err) != ErrorInvalidRequest {
		t.Fatalf("wrong mode error class = %q, want %q", ErrorClassOf(err), ErrorInvalidRequest)
	}

	response, err := marshalResponse(fixture.fileKey, "")
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := unmarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSecret(fileKey)
	if !bytes.Equal(fileKey, fixture.fileKey) {
		t.Fatal("response file key changed during wire round trip")
	}

	errorResponse, err := marshalResponse(nil, ErrorRecoveryMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalResponse(errorResponse); ErrorClassOf(err) != ErrorRecoveryMismatch {
		t.Fatalf("response error class = %q, want %q", ErrorClassOf(err), ErrorRecoveryMismatch)
	}
}

func TestReadyForTouchFrameIsCanonicalAndHasNoPayload(t *testing.T) {
	ready, err := marshalReady()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ready)
	if string(ready) != `{"version":2,"type":"ready_for_touch"}` {
		t.Fatalf("ready frame = %s", ready)
	}
	if err := unmarshalReady(ready); err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalResponse(ready); ErrorClassOf(err) != ErrorHelper {
		t.Fatal("ready frame was accepted as a terminal response")
	}

	for name, payload := range map[string]string{
		"wrong version": `{"version":1,"type":"ready_for_touch"}`,
		"wrong type":    `{"version":2,"type":"ready"}`,
		"payload":       `{"version":2,"type":"ready_for_touch","payload":true}`,
		"whitespace":    ` {"version":2,"type":"ready_for_touch"}`,
		"terminal":      `{"version":2,"ok":false,"error":"pin_provider_failed"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := unmarshalReady([]byte(payload)); ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q", ErrorClassOf(err))
			}
		})
	}
}

func TestResponseFileKeyRequiresExactByteArray(t *testing.T) {
	valid := `{"version":2,"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,255]}`
	fileKey, err := unmarshalResponse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSecret(fileKey)
	if len(fileKey) != fileKeySize || fileKey[15] != 255 {
		t.Fatal("valid byte-array file key changed during decoding")
	}

	invalid := map[string]string{
		"missing":        `{"version":2,"ok":true}`,
		"null":           `{"version":2,"ok":true,"file_key":null}`,
		"short":          `{"version":2,"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14]}`,
		"long":           `{"version":2,"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}`,
		"negative":       `{"version":2,"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,-1]}`,
		"out of range":   `{"version":2,"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,256]}`,
		"fraction":       `{"version":2,"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1.5]}`,
		"string":         `{"version":2,"ok":true,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,"15"]}`,
		"error with key": `{"version":2,"ok":false,"file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],"error":"recovery_mismatch"}`,
		"error null key": `{"version":2,"ok":false,"file_key":null,"error":"recovery_mismatch"}`,
	}
	for name, payload := range invalid {
		t.Run(name, func(t *testing.T) {
			key, err := unmarshalResponse([]byte(payload))
			ClearSecret(key)
			if ErrorClassOf(err) != ErrorHelper {
				t.Fatalf("error class = %q, want %q", ErrorClassOf(err), ErrorHelper)
			}
		})
	}
}

func TestResponseEncodingContainsNoBase64FileKeyString(t *testing.T) {
	fileKey := []byte("0123456789abcdef")
	payload, err := marshalResponse(fileKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if bytes.Contains(payload, []byte(`"file_key":"`)) || bytes.Contains(payload, []byte("MDEyMzQ1Njc4OWFiY2RlZg")) {
		t.Fatal("success response encoded the file key as an immutable base64 string")
	}
	if !bytes.Contains(payload, []byte(`"file_key":[`)) {
		t.Fatal("success response did not encode a byte array")
	}
}

func TestFrameBoundsAndTrailingData(t *testing.T) {
	var framed bytes.Buffer
	if err := writeFrame(&framed, []byte("request"), maxRequestFrame); err != nil {
		t.Fatal(err)
	}
	payload, err := readFrame(&framed, maxRequestFrame)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "request" || ensureEOF(&framed) != nil {
		t.Fatal("valid frame did not round trip")
	}

	for _, size := range []uint32{0, maxRequestFrame + 1} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if _, err := readFrame(bytes.NewReader(header[:]), maxRequestFrame); err == nil {
			t.Fatalf("accepted frame size %d", size)
		}
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 2, 1}), maxRequestFrame); err == nil {
		t.Fatal("accepted a truncated frame")
	}
	if err := ensureEOF(strings.NewReader("x")); err == nil {
		t.Fatal("accepted trailing frame data")
	}
	if err := writeFrame(io.Discard, make([]byte, maxRequestFrame+1), maxRequestFrame); err == nil {
		t.Fatal("wrote an oversized frame")
	}
}

func TestErrorMessagesNeverIncludeWrappedErrors(t *testing.T) {
	secret := "op://private/vault/item and 123456"
	err := errors.New(secret)
	if got := classError(ErrorHelper).Error(); strings.Contains(got, secret) {
		t.Fatal("classified error included secret")
	}
	if ErrorClassOf(err) != ErrorHelper {
		t.Fatal("unclassified error did not collapse to helper_failed")
	}
}
