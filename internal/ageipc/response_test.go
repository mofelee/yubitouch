package ageipc

import (
	"bytes"
	"testing"
)

func TestResponseFileKeyRequiresExactByteArray(t *testing.T) {
	valid := `{"version":1,"status":"ok","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,255]}`
	fileKey, err := unmarshalResponse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fileKey)
	if len(fileKey) != fileKeySize || fileKey[15] != 255 {
		t.Fatal("valid byte-array file key changed during decoding")
	}

	invalid := map[string]string{
		"missing":        `{"version":1,"status":"ok"}`,
		"null":           `{"version":1,"status":"ok","file_key":null}`,
		"short":          `{"version":1,"status":"ok","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14]}`,
		"long":           `{"version":1,"status":"ok","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}`,
		"negative":       `{"version":1,"status":"ok","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,-1]}`,
		"out of range":   `{"version":1,"status":"ok","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,256]}`,
		"fraction":       `{"version":1,"status":"ok","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1.5]}`,
		"string":         `{"version":1,"status":"ok","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,"15"]}`,
		"error with key": `{"version":1,"status":"error","file_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],"error":"pin_failed"}`,
		"error null key": `{"version":1,"status":"error","file_key":null,"error":"pin_failed"}`,
	}
	for name, payload := range invalid {
		t.Run(name, func(t *testing.T) {
			key, err := unmarshalResponse([]byte(payload))
			clear(key)
			assertErrorClass(t, err, ClassProtocolFailure)
		})
	}
}

func TestResponseEncodingContainsNoBase64FileKeyString(t *testing.T) {
	fileKey := []byte("0123456789abcdef")
	payload, err := marshalSuccess(fileKey)
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
