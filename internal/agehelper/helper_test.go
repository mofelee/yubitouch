package agehelper

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
)

type helperFixture struct {
	cfg                 config.Config
	hardwarePrivate     *ecdh.PrivateKey
	hardwareEnvelope    ageprofile.Envelope
	recoveryEnvelope    ageprofile.Envelope
	recoveryIdentity    string
	recoveryIdentityRef string
	fileKey             []byte
}

func newHelperFixture(t *testing.T) helperFixture {
	t.Helper()
	hardwarePrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var hardwarePublic ageprofile.PublicKey
	copy(hardwarePublic[:], hardwarePrivate.PublicKey().Bytes())
	recoveryIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recoveryPublic, err := ageprofile.ParseNativeRecipient(recoveryIdentity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ageprofile.NewRecipient(hardwarePublic, &recoveryPublic)
	if err != nil {
		t.Fatal(err)
	}
	fileKey := []byte("0123456789abcdef")
	stanzas, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	hardwareEnvelope, err := ageprofile.ParseEnvelope(stanzas[0])
	if err != nil {
		t.Fatal(err)
	}
	recoveryEnvelope, err := ageprofile.ParseEnvelope(stanzas[1])
	if err != nil {
		t.Fatal(err)
	}
	const identityRef = "op://Personal/YubiTouch Recovery/identity"
	return helperFixture{
		cfg: config.Config{
			OnePasswordAccount: "Personal",
			YKCS11Path:         "/provider/libykcs11.dylib",
			Age: &config.AgeConfig{
				Serial:    "12345678",
				Slot:      "82",
				Algorithm: "x25519",
				PublicKey: base64.RawURLEncoding.EncodeToString(hardwarePublic[:]),
				Recovery: &config.AgeRecovery{
					Provider:    "1password",
					IdentityRef: identityRef,
					Recipient:   recoveryIdentity.Recipient().String(),
				},
			},
		},
		hardwarePrivate:     hardwarePrivate,
		hardwareEnvelope:    hardwareEnvelope,
		recoveryEnvelope:    recoveryEnvelope,
		recoveryIdentity:    recoveryIdentity.String(),
		recoveryIdentityRef: identityRef,
		fileKey:             fileKey,
	}
}

func TestInternalHardwareSuccessUsesPINAndNeverRecovery(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	var output bytes.Buffer
	pinCalls := 0
	deriveCalls := 0
	recoveryCalls := 0
	deps := successfulDependencies(fixture)
	deps.resolvePIN = func(context.Context, config.Config) ([]byte, error) {
		pinCalls++
		return []byte("123456"), nil
	}
	deps.deriveHardware = func(_ context.Context, _ config.Config, target agehardware.Target, pinValue []byte, peer [32]byte, ready func() error) ([32]byte, error) {
		deriveCalls++
		if target.Serial != fixture.cfg.Age.Serial || target.Slot != fixture.cfg.Age.Slot || string(pinValue) != "123456" {
			t.Fatal("hardware helper did not pass the configured target and resolved PIN")
		}
		if err := ready(); err != nil {
			return [32]byte{}, err
		}
		peerKey, err := ecdh.X25519().NewPublicKey(peer[:])
		if err != nil {
			t.Fatal(err)
		}
		shared, err := fixture.hardwarePrivate.ECDH(peerKey)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(shared)
		var result [32]byte
		copy(result[:], shared)
		return result, nil
	}
	deps.resolveRecovery = func(context.Context, string, string) (string, error) {
		recoveryCalls++
		return "", errors.New("must not be called")
	}

	handled, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if !handled || code != 0 {
		t.Fatalf("handled = %t, code = %d", handled, code)
	}
	got := responseFileKey(t, &output)
	defer ClearSecret(got)
	if !bytes.Equal(got, fixture.fileKey) {
		t.Fatal("hardware helper returned the wrong file key")
	}
	if pinCalls != 1 || deriveCalls != 1 || recoveryCalls != 0 {
		t.Fatalf("PIN calls = %d, derive calls = %d, recovery calls = %d", pinCalls, deriveCalls, recoveryCalls)
	}
}

func TestInternalRecoverySuccessResolvesIdentityExactlyOnce(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.recoveryEnvelope}, ModeRecovery)
	var output bytes.Buffer
	resolveCalls := 0
	deps := successfulDependencies(fixture)
	deps.resolvePIN = func(context.Context, config.Config) ([]byte, error) {
		t.Fatal("recovery helper attempted to resolve a PIN")
		return nil, nil
	}
	deps.deriveHardware = func(context.Context, config.Config, agehardware.Target, []byte, [32]byte, func() error) ([32]byte, error) {
		t.Fatal("recovery helper attempted a hardware operation")
		return [32]byte{}, nil
	}
	deps.resolveRecovery = func(_ context.Context, account, reference string) (string, error) {
		resolveCalls++
		if account != fixture.cfg.OnePasswordAccount || reference != fixture.recoveryIdentityRef {
			t.Fatal("recovery helper changed the account or identity reference")
		}
		return fixture.recoveryIdentity, nil
	}

	handled, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeRecovery), "/home/test", deps)
	if !handled || code != 0 {
		t.Fatalf("handled = %t, code = %d", handled, code)
	}
	got := responseFileKey(t, &output)
	defer ClearSecret(got)
	if !bytes.Equal(got, fixture.fileKey) || resolveCalls != 1 {
		t.Fatalf("recovery result mismatch or resolver calls = %d", resolveCalls)
	}
	if bytes.Contains(output.Bytes(), []byte(fixture.recoveryIdentity)) || bytes.Contains(output.Bytes(), []byte(fixture.recoveryIdentityRef)) {
		t.Fatal("recovery response leaked the identity or reference")
	}
}

func TestInternalHardwareReadyContinueOrder(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	events := make([]string, 0, 10)
	record := func(event string) { events = append(events, event) }
	authentication := 0

	deps := successfulDependencies(fixture)
	deps.verifyParent = func() error {
		authentication++
		record([]string{"auth1", "auth2", "auth3"}[authentication-1])
		return nil
	}
	deps.watchParentDeath = func(func(string) string) (func(), error) {
		record("watch")
		return func() {}, nil
	}
	deps.openContinue = func(func(string) string) (io.ReadCloser, error) {
		record("fd4")
		return &tracingContinueReader{
			reader: bytes.NewReader([]byte{hardwareContinueSignal}),
			onRead: func() { record("continue") },
		}, nil
	}
	deps.loadConfig = func(string, string) (config.Config, error) {
		record("config")
		return fixture.cfg, nil
	}
	deps.resolvePIN = func(context.Context, config.Config) ([]byte, error) {
		record("pin")
		return []byte("123456"), nil
	}
	deps.deriveHardware = func(_ context.Context, _ config.Config, _ agehardware.Target, _ []byte, peer [32]byte, ready func() error) ([32]byte, error) {
		record("login")
		if err := ready(); err != nil {
			return [32]byte{}, err
		}
		record("derive")
		return fixtureSharedSecret(t, fixture, peer), nil
	}
	output := readyTracingBuffer{onReady: func() { record("ready") }}

	handled, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if !handled || code != 0 {
		t.Fatalf("handled = %t, code = %d", handled, code)
	}
	got := responseFileKey(t, &output.Buffer)
	defer ClearSecret(got)
	if !bytes.Equal(got, fixture.fileKey) {
		t.Fatal("hardware helper returned the wrong file key")
	}
	want := "auth1,watch,fd4,config,auth2,pin,login,ready,continue,auth3,derive"
	if got := strings.Join(events, ","); got != want {
		t.Fatalf("event order = %q, want %q", got, want)
	}
}

func TestInternalHardwarePINFailureDoesNotSignalReadyOrReadContinue(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	var output bytes.Buffer
	continueRead := false
	deriveCalls := 0
	deps := successfulDependencies(fixture)
	deps.resolvePIN = func(context.Context, config.Config) ([]byte, error) {
		return nil, errors.New("PIN provider unavailable")
	}
	deps.openContinue = func(func(string) string) (io.ReadCloser, error) {
		return &tracingContinueReader{
			reader: bytes.NewReader([]byte{hardwareContinueSignal}),
			onRead: func() { continueRead = true },
		}, nil
	}
	deps.deriveHardware = func(context.Context, config.Config, agehardware.Target, []byte, [32]byte, func() error) ([32]byte, error) {
		deriveCalls++
		return [32]byte{}, nil
	}

	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if code != helperFailureExitCode || outputStartsWithReady(t, output.Bytes()) {
		t.Fatalf("code = %d, ready = %t", code, outputStartsWithReady(t, output.Bytes()))
	}
	if responseErrorClass(t, &output) != ErrorPINProvider {
		t.Fatal("PIN failure returned the wrong error class")
	}
	if continueRead || deriveCalls != 0 {
		t.Fatalf("continue read = %t, derive calls = %d", continueRead, deriveCalls)
	}
}

func TestInternalHardwareLoginFailureDoesNotSignalReadyOrReadContinue(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	var output bytes.Buffer
	continueRead := false
	deriveCalls := 0
	deps := successfulDependencies(fixture)
	deps.openContinue = func(func(string) string) (io.ReadCloser, error) {
		return &tracingContinueReader{
			reader: bytes.NewReader([]byte{hardwareContinueSignal}),
			onRead: func() { continueRead = true },
		}, nil
	}
	deps.deriveHardware = func(context.Context, config.Config, agehardware.Target, []byte, [32]byte, func() error) ([32]byte, error) {
		deriveCalls++
		return [32]byte{}, agehardware.ErrPINLoginFailed
	}

	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if code != helperFailureExitCode || outputStartsWithReady(t, output.Bytes()) {
		t.Fatalf("code = %d, ready = %t", code, outputStartsWithReady(t, output.Bytes()))
	}
	if responseErrorClass(t, &output) != ErrorHardwarePIN {
		t.Fatal("hardware login failure returned the wrong error class")
	}
	if continueRead || deriveCalls != 1 {
		t.Fatalf("continue read = %t, derive calls = %d", continueRead, deriveCalls)
	}
}

func TestInternalHardwareRejectsInvalidContinueSignals(t *testing.T) {
	fixture := newHelperFixture(t)
	for name, payload := range map[string][]byte{
		"EOF":       nil,
		"wrong":     {hardwareContinueSignal + 1},
		"duplicate": {hardwareContinueSignal, hardwareContinueSignal},
	} {
		t.Run(name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.json")
			input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
			var output bytes.Buffer
			deriveCalls := 0
			deps := successfulDependencies(fixture)
			deps.openContinue = testContinueReader(payload)
			deps.deriveHardware = func(_ context.Context, _ config.Config, _ agehardware.Target, _ []byte, _ [32]byte, ready func() error) ([32]byte, error) {
				if err := ready(); err != nil {
					return [32]byte{}, err
				}
				deriveCalls++
				return [32]byte{}, nil
			}

			_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
			if code != helperFailureExitCode || !outputStartsWithReady(t, output.Bytes()) {
				t.Fatalf("code = %d, ready = %t", code, outputStartsWithReady(t, output.Bytes()))
			}
			if responseErrorClass(t, &output) != ErrorHelper || deriveCalls != 0 {
				t.Fatalf("derive calls = %d", deriveCalls)
			}
		})
	}
}

func TestInternalHardwareReauthenticatesParentAfterContinue(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	var output bytes.Buffer
	authentication := 0
	deriveCalls := 0
	deps := successfulDependencies(fixture)
	deps.verifyParent = func() error {
		authentication++
		if authentication == 3 {
			return errors.New("parent changed after continue")
		}
		return nil
	}
	deps.deriveHardware = func(_ context.Context, _ config.Config, _ agehardware.Target, _ []byte, _ [32]byte, ready func() error) ([32]byte, error) {
		if err := ready(); err != nil {
			return [32]byte{}, err
		}
		deriveCalls++
		return [32]byte{}, nil
	}

	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if code != helperFailureExitCode || !outputStartsWithReady(t, output.Bytes()) || responseErrorClass(t, &output) != ErrorHelper {
		t.Fatalf("code = %d, authentication calls = %d", code, authentication)
	}
	if authentication != 3 || deriveCalls != 0 {
		t.Fatalf("authentication calls = %d, derive calls = %d", authentication, deriveCalls)
	}
}

func TestInternalHardwareRequiresExactlyOneReadyCallback(t *testing.T) {
	fixture := newHelperFixture(t)
	for _, test := range []struct {
		name      string
		callbacks int
		wantReady bool
	}{
		{"missing", 0, false},
		{"repeated", 2, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.json")
			input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
			var output bytes.Buffer
			continueRead := 0
			deps := successfulDependencies(fixture)
			deps.openContinue = func(func(string) string) (io.ReadCloser, error) {
				return &tracingContinueReader{
					reader: bytes.NewReader([]byte{hardwareContinueSignal}),
					onRead: func() { continueRead++ },
				}, nil
			}
			deps.deriveHardware = func(_ context.Context, _ config.Config, _ agehardware.Target, _ []byte, peer [32]byte, ready func() error) ([32]byte, error) {
				for callback := 0; callback < test.callbacks; callback++ {
					_ = ready()
				}
				return fixtureSharedSecret(t, fixture, peer), nil
			}

			_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
			if code != helperFailureExitCode || outputStartsWithReady(t, output.Bytes()) != test.wantReady {
				t.Fatalf("code = %d, ready = %t", code, outputStartsWithReady(t, output.Bytes()))
			}
			if responseErrorClass(t, &output) != ErrorHelper {
				t.Fatal("invalid readiness callback count returned the wrong error class")
			}
			wantContinueReads := 0
			if test.wantReady {
				wantContinueReads = 1
			}
			if continueRead != wantContinueReads {
				t.Fatalf("continue reads = %d, want %d", continueRead, wantContinueReads)
			}
		})
	}
}

func TestInternalSecondParentAuthenticationPrecedesPIN(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	var output bytes.Buffer
	authentication := 0
	configLoads := 0
	pinCalls := 0
	deriveCalls := 0
	deps := successfulDependencies(fixture)
	deps.loadConfig = func(string, string) (config.Config, error) {
		configLoads++
		return fixture.cfg, nil
	}
	deps.verifyParent = func() error {
		authentication++
		if authentication == 2 {
			return errors.New("parent changed while configuration was read")
		}
		return nil
	}
	deps.resolvePIN = func(context.Context, config.Config) ([]byte, error) {
		pinCalls++
		return []byte("123456"), nil
	}
	deps.deriveHardware = func(context.Context, config.Config, agehardware.Target, []byte, [32]byte, func() error) ([32]byte, error) {
		deriveCalls++
		return [32]byte{}, nil
	}

	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if code != helperFailureExitCode || outputStartsWithReady(t, output.Bytes()) || responseErrorClass(t, &output) != ErrorHelper {
		t.Fatalf("code = %d, authentication calls = %d", code, authentication)
	}
	if configLoads != 1 || authentication != 2 || pinCalls != 0 || deriveCalls != 0 {
		t.Fatalf("config loads = %d, authentication calls = %d, PIN calls = %d, derive calls = %d", configLoads, authentication, pinCalls, deriveCalls)
	}
}

func TestInternalHardwareOpensContinueBeforeConfigurationAndPIN(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	var output bytes.Buffer
	configLoads := 0
	pinCalls := 0
	deps := successfulDependencies(fixture)
	deps.openContinue = func(func(string) string) (io.ReadCloser, error) {
		return nil, errors.New("fd4 unavailable")
	}
	deps.loadConfig = func(string, string) (config.Config, error) {
		configLoads++
		return fixture.cfg, nil
	}
	deps.resolvePIN = func(context.Context, config.Config) ([]byte, error) {
		pinCalls++
		return []byte("123456"), nil
	}

	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if code != helperFailureExitCode || responseErrorClass(t, &output) != ErrorHelper {
		t.Fatalf("code = %d", code)
	}
	if configLoads != 0 || pinCalls != 0 {
		t.Fatalf("config loads = %d, PIN calls = %d", configLoads, pinCalls)
	}
}

func TestInternalRecoveryNeverOpensHardwareContinue(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.recoveryEnvelope}, ModeRecovery)
	var output bytes.Buffer
	deps := successfulDependencies(fixture)
	deps.openContinue = func(func(string) string) (io.ReadCloser, error) {
		t.Fatal("recovery helper opened fd4")
		return nil, nil
	}

	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeRecovery), "/home/test", deps)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	fileKey := responseFileKey(t, &output)
	ClearSecret(fileKey)
}

func TestInternalRecoveryRejectsContinueEnvironmentBeforeSensitiveReads(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.recoveryEnvelope}, ModeRecovery)
	var output bytes.Buffer
	configLoads := 0
	recoveryCalls := 0
	deps := successfulDependencies(fixture)
	deps.loadConfig = func(string, string) (config.Config, error) {
		configLoads++
		return fixture.cfg, nil
	}
	deps.resolveRecovery = func(context.Context, string, string) (string, error) {
		recoveryCalls++
		return fixture.recoveryIdentity, nil
	}
	baseEnvironment := helperEnvironment(configPath, ModeRecovery)
	getenv := func(name string) string {
		if name == hardwareContinueEnvironment {
			return "4"
		}
		return baseEnvironment(name)
	}

	_, code := runInternal(context.Background(), &input, &output, getenv, "/home/test", deps)
	if code != helperFailureExitCode || responseErrorClass(t, &output) != ErrorHelper {
		t.Fatalf("code = %d", code)
	}
	if configLoads != 0 || recoveryCalls != 0 {
		t.Fatalf("config loads = %d, recovery calls = %d", configLoads, recoveryCalls)
	}
}

func TestInternalRecoveryRejectsPrivateKeyMismatch(t *testing.T) {
	fixture := newHelperFixture(t)
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.recoveryEnvelope}, ModeRecovery)
	var output bytes.Buffer
	resolveCalls := 0
	deps := successfulDependencies(fixture)
	deps.resolveRecovery = func(context.Context, string, string) (string, error) {
		resolveCalls++
		return other.String(), nil
	}

	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeRecovery), "/home/test", deps)
	if code != helperFailureExitCode || responseErrorClass(t, &output) != ErrorRecoveryMismatch {
		t.Fatalf("code = %d, want recovery mismatch", code)
	}
	if resolveCalls != 1 || bytes.Contains(output.Bytes(), []byte(other.String())) {
		t.Fatal("mismatch path resolved more than once or leaked the identity")
	}
}

func TestInternalRejectsMalformedInputBeforeLoadingConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	var input bytes.Buffer
	var header [4]byte
	header[3] = 3
	input.Write(header[:])
	input.WriteString("bad")
	var output bytes.Buffer
	loads := 0
	deps := productionHelperDependencies()
	deps.disableCoreDump = func() error { return nil }
	deps.verifyParent = func() error { return nil }
	deps.watchParentDeath = noParentDeathWatch
	deps.openContinue = testContinueReader([]byte{hardwareContinueSignal})
	deps.loadConfig = func(string, string) (config.Config, error) {
		loads++
		return config.Config{}, nil
	}
	_, code := runInternal(context.Background(), &input, &output, helperEnvironment(configPath, ModeHardware), "/home/test", deps)
	if code != helperFailureExitCode || loads != 0 || responseErrorClass(t, &output) != ErrorInvalidRequest {
		t.Fatalf("code = %d, loads = %d", code, loads)
	}
}

func TestInternalRejectsUnauthorizedParentBeforeSensitiveDependencies(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	var output bytes.Buffer
	loads := 0
	pinCalls := 0
	deriveCalls := 0
	recoveryCalls := 0
	deps := helperDependencies{
		disableCoreDump: func() error { return nil },
		verifyParent:    func() error { return errors.New("different executable") },
		loadConfig: func(string, string) (config.Config, error) {
			loads++
			return config.Config{}, nil
		},
		resolvePIN: func(context.Context, config.Config) ([]byte, error) {
			pinCalls++
			return []byte("must-not-resolve"), nil
		},
		deriveHardware: func(context.Context, config.Config, agehardware.Target, []byte, [32]byte, func() error) ([32]byte, error) {
			deriveCalls++
			return [32]byte{}, nil
		},
		resolveRecovery: func(context.Context, string, string) (string, error) {
			recoveryCalls++
			return "must-not-resolve", nil
		},
	}
	handled, code := runInternal(
		context.Background(),
		bytes.NewReader([]byte("malformed private request")),
		&output,
		helperEnvironment(configPath, ModeRecovery),
		"/home/test",
		deps,
	)
	if !handled || code != helperFailureExitCode || responseErrorClass(t, &output) != ErrorHelper {
		t.Fatalf("handled = %t, code = %d", handled, code)
	}
	if loads != 0 || pinCalls != 0 || deriveCalls != 0 || recoveryCalls != 0 {
		t.Fatalf("sensitive dependency calls = load:%d pin:%d derive:%d recovery:%d", loads, pinCalls, deriveCalls, recoveryCalls)
	}
}

func TestInternalRequiresParentDeathWatchBeforeLoadingConfig(t *testing.T) {
	fixture := newHelperFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := framedRequest(t, Request{Envelope: fixture.hardwareEnvelope}, ModeHardware)
	var output bytes.Buffer
	loads := 0
	deps := successfulDependencies(fixture)
	deps.watchParentDeath = nil
	deps.loadConfig = func(string, string) (config.Config, error) {
		loads++
		return fixture.cfg, nil
	}

	handled, code := runInternal(
		context.Background(),
		&input,
		&output,
		helperEnvironment(configPath, ModeHardware),
		"/home/test",
		deps,
	)
	if !handled || code != helperFailureExitCode || responseErrorClass(t, &output) != ErrorHelper {
		t.Fatalf("handled = %t, code = %d", handled, code)
	}
	if loads != 0 {
		t.Fatalf("configuration loads = %d, want 0", loads)
	}
}

func successfulDependencies(fixture helperFixture) helperDependencies {
	return helperDependencies{
		loadConfig:       func(string, string) (config.Config, error) { return fixture.cfg, nil },
		resolvePIN:       func(context.Context, config.Config) ([]byte, error) { return []byte("123456"), nil },
		resolveRecovery:  func(context.Context, string, string) (string, error) { return fixture.recoveryIdentity, nil },
		disableCoreDump:  func() error { return nil },
		verifyParent:     func() error { return nil },
		watchParentDeath: noParentDeathWatch,
		openContinue:     testContinueReader([]byte{hardwareContinueSignal}),
	}
}

func noParentDeathWatch(func(string) string) (func(), error) {
	return func() {}, nil
}

func framedRequest(t *testing.T, request Request, mode Mode) bytes.Buffer {
	t.Helper()
	encoded, err := marshalRequest(request, mode)
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

func helperEnvironment(configPath string, mode Mode) func(string) string {
	return func(name string) string {
		switch name {
		case internalModeEnvironment:
			return string(mode)
		case "YUBITOUCH_CONFIG":
			return configPath
		case hardwareContinueEnvironment:
			if mode == ModeHardware {
				return "4"
			}
			return ""
		default:
			return ""
		}
	}
}

func responseFileKey(t *testing.T, output *bytes.Buffer) []byte {
	t.Helper()
	encoded := terminalResponse(t, output)
	defer clear(encoded)
	fileKey, err := unmarshalResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return fileKey
}

func responseErrorClass(t *testing.T, output *bytes.Buffer) ErrorClass {
	t.Helper()
	encoded := terminalResponse(t, output)
	defer clear(encoded)
	_, err := unmarshalResponse(encoded)
	return ErrorClassOf(err)
}

func terminalResponse(t *testing.T, output *bytes.Buffer) []byte {
	t.Helper()
	encoded, err := readFrame(output, maxResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	if unmarshalReady(encoded) == nil {
		clear(encoded)
		encoded, err = readFrame(output, maxResponseFrame)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := ensureEOF(output); err != nil {
		clear(encoded)
		t.Fatal(err)
	}
	return encoded
}

func testContinueReader(payload []byte) func(func(string) string) (io.ReadCloser, error) {
	return func(func(string) string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(payload)), nil
	}
}

func fixtureSharedSecret(t *testing.T, fixture helperFixture, peer [32]byte) [32]byte {
	t.Helper()
	peerKey, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := fixture.hardwarePrivate.ECDH(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(shared)
	var result [32]byte
	copy(result[:], shared)
	return result
}

func outputStartsWithReady(t *testing.T, output []byte) bool {
	t.Helper()
	encoded, err := readFrame(bytes.NewReader(output), maxResponseFrame)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	return unmarshalReady(encoded) == nil
}

type readyTracingBuffer struct {
	bytes.Buffer
	onReady func()
	once    sync.Once
}

func (w *readyTracingBuffer) Write(payload []byte) (int, error) {
	if bytes.Equal(payload, []byte(`{"version":2,"type":"ready_for_touch"}`)) {
		w.once.Do(w.onReady)
	}
	return w.Buffer.Write(payload)
}

type tracingContinueReader struct {
	reader io.Reader
	onRead func()
	once   sync.Once
}

func (r *tracingContinueReader) Read(payload []byte) (int, error) {
	r.once.Do(r.onRead)
	return r.reader.Read(payload)
}

func (*tracingContinueReader) Close() error { return nil }
