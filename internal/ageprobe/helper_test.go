package ageprobe

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/config"
)

type fakePublicBackend struct {
	publicKey   [32]byte
	readErr     error
	probeResult agehardware.ProbeResult
	probeErr    error
	readCalls   int
	probeCalls  int
	closed      bool
	serial      string
	slot        string
	target      agehardware.Target
}

func (f *fakePublicBackend) ReadPublic(_ context.Context, serial, slot string) ([32]byte, error) {
	f.readCalls++
	f.serial = serial
	f.slot = slot
	return f.publicKey, f.readErr
}

func (f *fakePublicBackend) Probe(_ context.Context, target agehardware.Target) (agehardware.ProbeResult, error) {
	f.probeCalls++
	f.target = target
	return f.probeResult, f.probeErr
}

func (f *fakePublicBackend) Close() error {
	f.closed = true
	return nil
}

func TestInternalHelperReadsPublicKeyWithoutPrivateInputs(t *testing.T) {
	publicKey := testPublicKey(t)
	cfg := helperConfig(publicKey)
	backend := &fakePublicBackend{publicKey: publicKey}
	input := framedRequest(t, request{Operation: OperationReadPublic, Serial: cfg.Age.Serial, Slot: cfg.Age.Slot})
	var output bytes.Buffer

	handled, code := runInternal(context.Background(), &input, &output, helperEnvironment, "/home/test", helperDependencies{
		watchParentDeath: noParentDeathWatch,
		loadConfig: func(path, home string) (config.Config, error) {
			if path != "/private/config.json" || home != "/home/test" {
				t.Fatal("helper changed its config target")
			}
			return cfg, nil
		},
		newBackend: func(provider string) publicBackend {
			if provider != cfg.YKCS11Path {
				t.Fatal("helper changed the configured provider")
			}
			return backend
		},
	})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d", handled, code)
	}
	result, err := decodeHelperOutput(&output, OperationReadPublic)
	if err != nil {
		t.Fatal(err)
	}
	if result.PublicKey != publicKey || backend.readCalls != 1 || backend.probeCalls != 0 || !backend.closed {
		t.Fatalf("result/backend = %+v %+v", result, backend)
	}
	if backend.serial != cfg.Age.Serial || backend.slot != cfg.Age.Slot {
		t.Fatal("helper did not pass the framed target to ReadPublic")
	}
}

func TestInternalHelperProbeBindsConfigAndTarget(t *testing.T) {
	publicKey := testPublicKey(t)
	cfg := helperConfig(publicKey)
	backend := &fakePublicBackend{probeResult: agehardware.ProbeResult{State: agehardware.Connected}}
	input := framedRequest(t, request{
		Operation: OperationProbe,
		Serial:    cfg.Age.Serial,
		Slot:      cfg.Age.Slot,
		PublicKey: publicKey,
	})
	var output bytes.Buffer
	handled, code := runInternal(context.Background(), &input, &output, helperEnvironment, "/home/test", helperDependencies{
		loadConfig:       func(string, string) (config.Config, error) { return cfg, nil },
		newBackend:       func(string) publicBackend { return backend },
		watchParentDeath: noParentDeathWatch,
	})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d", handled, code)
	}
	result, err := decodeHelperOutput(&output, OperationProbe)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != agehardware.Connected || backend.probeCalls != 1 || backend.readCalls != 0 || backend.target.PublicKey != publicKey {
		t.Fatalf("result/backend = %+v %+v", result, backend)
	}
}

func TestInternalHelperProbeRejectsPublicKeyMismatch(t *testing.T) {
	publicKey := testPublicKey(t)
	otherPublicKey := publicKey
	otherPublicKey[0] ^= 1
	cfg := helperConfig(publicKey)
	backend := &fakePublicBackend{}
	input := framedRequest(t, request{
		Operation: OperationProbe,
		Serial:    cfg.Age.Serial,
		Slot:      cfg.Age.Slot,
		PublicKey: otherPublicKey,
	})
	var output bytes.Buffer
	_, code := runInternal(context.Background(), &input, &output, helperEnvironment, "/home/test", helperDependencies{
		loadConfig:       func(string, string) (config.Config, error) { return cfg, nil },
		newBackend:       func(string) publicBackend { return backend },
		watchParentDeath: noParentDeathWatch,
	})
	_, err := decodeHelperOutput(&output, OperationProbe)
	if code != helperFailureCode || ErrorClassOf(err) != ErrorTargetMismatch || backend.probeCalls != 0 {
		t.Fatalf("code=%d class=%q probe calls=%d", code, ErrorClassOf(err), backend.probeCalls)
	}
}

func TestInternalHelperProbeClassifications(t *testing.T) {
	publicKey := testPublicKey(t)
	cfg := helperConfig(publicKey)
	tests := []struct {
		name       string
		result     agehardware.ProbeResult
		err        error
		wantState  agehardware.ProbeState
		wantClass  ErrorClass
		wantExitOK bool
	}{
		{name: "not detected", result: agehardware.ProbeResult{State: agehardware.NotDetected}, wantState: agehardware.NotDetected, wantExitOK: true},
		{name: "mismatch", result: agehardware.ProbeResult{State: agehardware.Mismatch}, err: agehardware.ErrTargetMismatch, wantClass: ErrorTargetMismatch},
		{name: "unavailable", result: agehardware.ProbeResult{State: agehardware.Unavailable}, err: agehardware.ErrProbeUnavailable, wantClass: ErrorProbe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &fakePublicBackend{probeResult: test.result, probeErr: test.err}
			input := framedRequest(t, request{
				Operation: OperationProbe,
				Serial:    cfg.Age.Serial,
				Slot:      cfg.Age.Slot,
				PublicKey: publicKey,
			})
			var output bytes.Buffer
			_, code := runInternal(context.Background(), &input, &output, helperEnvironment, "/home/test", helperDependencies{
				loadConfig:       func(string, string) (config.Config, error) { return cfg, nil },
				newBackend:       func(string) publicBackend { return backend },
				watchParentDeath: noParentDeathWatch,
			})
			result, err := decodeHelperOutput(&output, OperationProbe)
			if test.wantExitOK {
				if code != 0 || err != nil || result.State != test.wantState {
					t.Fatalf("code=%d result=%+v err=%v", code, result, err)
				}
				return
			}
			if code != helperFailureCode || ErrorClassOf(err) != test.wantClass {
				t.Fatalf("code=%d class=%q, want %q", code, ErrorClassOf(err), test.wantClass)
			}
		})
	}
}

func TestInternalHelperRejectsTargetBeforeOpeningBackend(t *testing.T) {
	publicKey := testPublicKey(t)
	cfg := helperConfig(publicKey)
	requests := []request{
		{Operation: OperationReadPublic, Serial: "87654321", Slot: cfg.Age.Slot},
		{Operation: OperationReadPublic, Serial: cfg.Age.Serial, Slot: "83"},
	}
	for _, value := range requests {
		input := framedRequest(t, value)
		var output bytes.Buffer
		backendCalls := 0
		_, code := runInternal(context.Background(), &input, &output, helperEnvironment, "/home/test", helperDependencies{
			watchParentDeath: noParentDeathWatch,
			loadConfig:       func(string, string) (config.Config, error) { return cfg, nil },
			newBackend: func(string) publicBackend {
				backendCalls++
				return &fakePublicBackend{}
			},
		})
		if code != helperFailureCode || backendCalls != 0 {
			t.Fatalf("code=%d backend calls=%d", code, backendCalls)
		}
		_, err := decodeHelperOutput(&output, value.Operation)
		if ErrorClassOf(err) != ErrorTargetMismatch {
			t.Fatalf("class=%q, want %q", ErrorClassOf(err), ErrorTargetMismatch)
		}
	}
}

func TestInternalHelperRedactsBackendErrors(t *testing.T) {
	publicKey := testPublicKey(t)
	cfg := helperConfig(publicKey)
	const sensitive = "serial=12345678 op://private/reference"
	backend := &fakePublicBackend{readErr: errors.New(sensitive)}
	input := framedRequest(t, request{Operation: OperationReadPublic, Serial: cfg.Age.Serial, Slot: cfg.Age.Slot})
	var output bytes.Buffer
	_, code := runInternal(context.Background(), &input, &output, helperEnvironment, "/home/test", helperDependencies{
		loadConfig:       func(string, string) (config.Config, error) { return cfg, nil },
		newBackend:       func(string) publicBackend { return backend },
		watchParentDeath: noParentDeathWatch,
	})
	if code != helperFailureCode || bytes.Contains(output.Bytes(), []byte(sensitive)) {
		t.Fatalf("code=%d output leaked backend error", code)
	}
	_, err := decodeHelperOutput(&output, OperationReadPublic)
	if ErrorClassOf(err) != ErrorProbe {
		t.Fatalf("class=%q, want %q", ErrorClassOf(err), ErrorProbe)
	}
}

func TestInternalHelperRequiresParentWatchEnvironmentBeforeLoadingConfig(t *testing.T) {
	publicKey := testPublicKey(t)
	cfg := helperConfig(publicKey)
	input := framedRequest(t, request{Operation: OperationReadPublic, Serial: cfg.Age.Serial, Slot: cfg.Age.Slot})
	var output bytes.Buffer
	loads := 0
	deps := helperDependencies{
		loadConfig: func(string, string) (config.Config, error) {
			loads++
			return cfg, nil
		},
		newBackend:       func(string) publicBackend { return &fakePublicBackend{} },
		watchParentDeath: startParentLifetimeWatch,
	}

	handled, code := runInternal(context.Background(), &input, &output, helperEnvironment, "/home/test", deps)
	if !handled || code != helperFailureCode {
		t.Fatalf("handled=%v code=%d", handled, code)
	}
	_, err := decodeHelperOutput(&output, OperationReadPublic)
	if ErrorClassOf(err) != ErrorHelper {
		t.Fatalf("class=%q, want %q", ErrorClassOf(err), ErrorHelper)
	}
	if loads != 0 {
		t.Fatalf("configuration loads=%d, want 0", loads)
	}
}

func TestInternalHelperModeAndConfigurationFailures(t *testing.T) {
	if handled, code := RunInternalFromEnvironment(context.Background(), bytes.NewReader(nil), &bytes.Buffer{}, func(string) string { return "" }, "/home/test"); handled || code != 0 {
		t.Fatalf("normal invocation handled=%v code=%d", handled, code)
	}

	var output bytes.Buffer
	handled, code := runInternal(context.Background(), bytes.NewReader(nil), &output, func(name string) string {
		if name == internalModeEnvironment {
			return "invalid"
		}
		return ""
	}, "/home/test", helperDependencies{})
	if !handled || code != helperFailureCode {
		t.Fatalf("invalid mode handled=%v code=%d", handled, code)
	}
}

func helperConfig(publicKey [32]byte) config.Config {
	return config.Config{
		YKCS11Path: "/opt/homebrew/opt/yubico-piv-tool/lib/libykcs11.dylib",
		Age: &config.AgeConfig{
			Serial:    "12345678",
			Slot:      "82",
			Algorithm: "x25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(publicKey[:]),
		},
	}
}

func helperEnvironment(name string) string {
	switch name {
	case internalModeEnvironment:
		return "1"
	case "YUBITOUCH_CONFIG":
		return "/private/config.json"
	default:
		return ""
	}
}

func noParentDeathWatch(func(string) string) (func(), error) {
	return func() {}, nil
}

func framedRequest(t *testing.T, value request) bytes.Buffer {
	t.Helper()
	encoded, err := marshalRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	var input bytes.Buffer
	if err := writeFrame(&input, encoded, maxRequestFrame); err != nil {
		t.Fatal(err)
	}
	return input
}

func decodeHelperOutput(output *bytes.Buffer, operation Operation) (response, error) {
	encoded, err := readFrame(output, maxResponseFrame)
	if err != nil {
		return response{}, err
	}
	defer clear(encoded)
	if err := ensureEOF(output); err != nil {
		return response{}, err
	}
	return unmarshalResponse(encoded, operation)
}
