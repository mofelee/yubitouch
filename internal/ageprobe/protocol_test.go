package ageprobe

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/mofelee/yubitouch/internal/agehardware"
)

func TestRequestRoundTrip(t *testing.T) {
	publicKey := testPublicKey(t)
	requests := []request{
		{Operation: OperationReadPublic, Serial: "12345678", Slot: "82"},
		{Operation: OperationProbe, Serial: "12345678", Slot: "9d", PublicKey: publicKey},
	}
	for _, want := range requests {
		encoded, err := marshalRequest(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := unmarshalRequest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("request = %+v, want %+v", got, want)
		}
	}
}

func TestResponseRoundTrip(t *testing.T) {
	publicKey := testPublicKey(t)
	tests := []struct {
		operation Operation
		response  response
	}{
		{OperationReadPublic, response{PublicKey: publicKey}},
		{OperationProbe, response{State: agehardware.Connected}},
		{OperationProbe, response{State: agehardware.NotDetected}},
	}
	for _, test := range tests {
		encoded, err := marshalSuccess(test.operation, test.response)
		if err != nil {
			t.Fatal(err)
		}
		got, err := unmarshalResponse(encoded, test.operation)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.response {
			t.Fatalf("response = %+v, want %+v", got, test.response)
		}
	}

	for _, class := range []ErrorClass{ErrorInvalidRequest, ErrorConfiguration, ErrorNotDetected, ErrorTargetMismatch, ErrorProbe, ErrorCanceled, ErrorTimeout, ErrorHelper} {
		_, err := unmarshalResponse(marshalFailure(class), OperationProbe)
		if ErrorClassOf(err) != class {
			t.Fatalf("failure class = %q, want %q", ErrorClassOf(err), class)
		}
	}
}

func TestProtocolRejectsMalformedOrNoncanonicalInput(t *testing.T) {
	publicKey := testPublicKey(t)
	valid, err := marshalRequest(request{Operation: OperationProbe, Serial: "12345678", Slot: "82", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		nil,
		append(append([]byte(nil), valid...), '\n'),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":2`), 1),
		bytes.Replace(valid, []byte(`"operation":"probe"`), []byte(`"operation":"derive"`), 1),
		bytes.Replace(valid, []byte(`"serial":"12345678"`), []byte(`"serial":"012345678"`), 1),
		bytes.Replace(valid, []byte(`"slot":"82"`), []byte(`"slot":"81"`), 1),
		bytes.Replace(valid, []byte(`"slot":"82"`), []byte(`"slot":"9A"`), 1),
		bytes.Replace(valid, []byte(`"public_key":`), []byte(`"unknown":1,"public_key":`), 1),
	}
	for _, encoded := range tests {
		if _, err := unmarshalRequest(encoded); ErrorClassOf(err) != ErrorInvalidRequest {
			t.Fatalf("malformed request accepted: %q (%v)", encoded, err)
		}
	}

	readRequest, err := marshalRequest(request{Operation: OperationReadPublic, Serial: "12345678", Slot: "82"})
	if err != nil {
		t.Fatal(err)
	}
	withPublic := bytes.Replace(readRequest, []byte(`"slot":"82"`), []byte(`"slot":"82","public_key":"AAAA"`), 1)
	if _, err := unmarshalRequest(withPublic); ErrorClassOf(err) != ErrorInvalidRequest {
		t.Fatal("read-public request with a public key was accepted")
	}
}

func TestFramesAreBounded(t *testing.T) {
	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxRequestFrame+1)
	oversized.Write(header[:])
	if _, err := readFrame(&oversized, maxRequestFrame); err == nil {
		t.Fatal("oversized frame was accepted")
	}
	if err := writeFrame(&bytes.Buffer{}, bytes.Repeat([]byte{'x'}, maxResponseFrame+1), maxResponseFrame); err == nil {
		t.Fatal("oversized response was written")
	}
}

func TestClassErrorsWrapOnlyExpectedSentinels(t *testing.T) {
	if !errors.Is(classError(ErrorNotDetected), agehardware.ErrNotDetected) {
		t.Fatal("not-detected class does not wrap the hardware sentinel")
	}
	if !errors.Is(classError(ErrorTargetMismatch), agehardware.ErrTargetMismatch) {
		t.Fatal("target-mismatch class does not wrap the hardware sentinel")
	}
	for _, class := range []ErrorClass{ErrorInvalidRequest, ErrorConfiguration, ErrorProbe, ErrorHelper} {
		if strings.Contains((&ClassError{Class: class}).Error(), "12345678") {
			t.Fatal("class error exposed target data")
		}
	}
}

func testPublicKey(t *testing.T) [32]byte {
	t.Helper()
	scalar := bytes.Repeat([]byte{0x42}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(scalar)
	clear(scalar)
	if err != nil {
		t.Fatal(err)
	}
	var publicKey [32]byte
	copy(publicKey[:], privateKey.PublicKey().Bytes())
	return publicKey
}
