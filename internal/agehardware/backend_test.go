package agehardware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

const (
	testSerial        = "12345678"
	testPublicObject  = pkcs11.ObjectHandle(11)
	testPrivateObject = pkcs11.ObjectHandle(22)
	testDerivedObject = pkcs11.ObjectHandle(33)
)

func TestPIVSlotID(t *testing.T) {
	valid := map[string]byte{
		"9a": 1,
		"9A": 1,
		"9e": 2,
		"9E": 2,
		"9c": 3,
		"9C": 3,
		"9d": 4,
		"9D": 4,
	}
	for value := 0x82; value <= 0x95; value++ {
		valid[fmt.Sprintf("%02x", value)] = byte(value-0x82) + 5
		valid[fmt.Sprintf("%02X", value)] = byte(value-0x82) + 5
	}
	for slot, want := range valid {
		t.Run(slot, func(t *testing.T) {
			got, err := pivSlotID(slot)
			if err != nil || got != want {
				t.Fatalf("pivSlotID(%q) = %d, %v; want %d", slot, got, err, want)
			}
		})
	}

	for _, slot := range []string{"", "9", " 9a", "9a ", "0x82", "81", "96", "9b", "ff", "zz", "082"} {
		t.Run("invalid_"+slot, func(t *testing.T) {
			if _, err := pivSlotID(slot); !errors.Is(err, ErrTargetMismatch) {
				t.Fatalf("pivSlotID(%q) error = %v", slot, err)
			}
		})
	}
}

func TestReadPublicAndProbeStates(t *testing.T) {
	publicKey := bytes32(1)
	tests := []struct {
		name      string
		module    *fakeModule
		targetKey [32]byte
		wantState ProbeState
		wantErr   error
	}{
		{
			name:      "not detected",
			module:    &fakeModule{},
			targetKey: publicKey,
			wantState: NotDetected,
		},
		{
			name: "only another token",
			module: &fakeModule{
				slots:      []uint{7},
				tokenInfos: map[uint]pkcs11.TokenInfo{7: {SerialNumber: "87654321"}},
			},
			targetKey: publicKey,
			wantState: Mismatch,
			wantErr:   ErrTargetMismatch,
		},
		{
			name:      "connected",
			module:    publicFake(publicKey),
			targetKey: publicKey,
			wantState: Connected,
		},
		{
			name:      "different public key",
			module:    publicFake(publicKey),
			targetKey: bytes32(91),
			wantState: Mismatch,
			wantErr:   ErrTargetMismatch,
		},
		{
			name: "duplicate public object",
			module: &fakeModule{
				slots:       []uint{7},
				tokenInfos:  map[uint]pkcs11.TokenInfo{7: {SerialNumber: testSerial}},
				findResults: [][]pkcs11.ObjectHandle{{testPublicObject, 12}},
			},
			targetKey: publicKey,
			wantState: Mismatch,
			wantErr:   ErrTargetMismatch,
		},
		{
			name: "duplicate public object on second page",
			module: &fakeModule{
				slots:       []uint{7},
				tokenInfos:  map[uint]pkcs11.TokenInfo{7: {SerialNumber: testSerial}},
				findResults: [][]pkcs11.ObjectHandle{{testPublicObject}, {12}},
			},
			targetKey: publicKey,
			wantState: Mismatch,
			wantErr:   ErrTargetMismatch,
		},
		{
			name: "malformed public object",
			module: &fakeModule{
				slots:       []uint{7},
				tokenInfos:  map[uint]pkcs11.TokenInfo{7: {SerialNumber: testSerial}},
				findResults: [][]pkcs11.ObjectHandle{{testPublicObject}, nil},
				attributes:  map[pkcs11.ObjectHandle][]*pkcs11.Attribute{testPublicObject: {pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, publicKey[:])}},
			},
			targetKey: publicKey,
			wantState: Mismatch,
			wantErr:   ErrTargetMismatch,
		},
		{
			name: "session unavailable",
			module: &fakeModule{
				slots:      []uint{7},
				tokenInfos: map[uint]pkcs11.TokenInfo{7: {SerialNumber: testSerial}},
				openError:  errors.New("provider session details"),
			},
			targetKey: publicKey,
			wantState: Unavailable,
			wantErr:   ErrProbeUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := fakeBackend(test.module)
			result, err := backend.Probe(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: test.targetKey})
			if result.State != test.wantState {
				t.Fatalf("probe state = %q, want %q (error %v)", result.State, test.wantState, err)
			}
			if test.wantErr == nil && err != nil {
				t.Fatalf("probe error = %v", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("probe error = %v, want %v", err, test.wantErr)
			}
			if test.module.loginCalls != 0 {
				t.Fatalf("probe called Login %d times", test.module.loginCalls)
			}
			if len(test.module.openFlags) > 0 && test.module.openFlags[0] != pkcs11.CKF_SERIAL_SESSION {
				t.Fatalf("probe session flags = %#x", test.module.openFlags[0])
			}
		})
	}
}

func TestReadPublicClassifiesAbsenceAndValidatesBeforeProvider(t *testing.T) {
	module := &fakeModule{}
	backend := fakeBackend(module)
	if _, err := backend.ReadPublic(context.Background(), testSerial, "82"); !errors.Is(err, ErrNotDetected) {
		t.Fatalf("empty provider error = %v", err)
	}

	for _, target := range []struct{ serial, slot string }{
		{serial: "012345678", slot: "82"},
		{serial: "0", slot: "82"},
		{serial: testSerial, slot: " 82"},
		{serial: testSerial, slot: "9b"},
	} {
		before := module.initializeCalls
		if _, err := backend.ReadPublic(context.Background(), target.serial, target.slot); !errors.Is(err, ErrTargetMismatch) {
			t.Fatalf("ReadPublic(%q, %q) error = %v", target.serial, target.slot, err)
		}
		if module.initializeCalls != before {
			t.Fatal("invalid target initialized the provider")
		}
	}
}

func TestDeriveUsesExpectedX25519ObjectsAndTemplate(t *testing.T) {
	publicKey := bytes32(1)
	peer := bytes32(65)
	shared := bytes32(129)
	module := deriveFake(publicKey, shared)
	backend := fakeBackend(module)
	var gotKDF uint
	var gotSharedData, gotPeer []byte
	backend.newECDHParams = func(kdf uint, sharedData []byte, publicKeyData []byte) *pkcs11.ECDH1DeriveParams {
		gotKDF = kdf
		gotSharedData = append([]byte(nil), sharedData...)
		gotPeer = append([]byte(nil), publicKeyData...)
		return pkcs11.NewECDH1DeriveParams(kdf, sharedData, publicKeyData)
	}

	got, err := backend.Derive(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey}, []byte("654321"), peer)
	if err != nil {
		t.Fatal(err)
	}
	if got != shared {
		t.Fatalf("derived secret does not match")
	}
	if module.loginUser != pkcs11.CKU_USER || module.loginPIN != "654321" || module.loginCalls != 1 {
		t.Fatalf("login = user %d pin %q calls %d", module.loginUser, module.loginPIN, module.loginCalls)
	}
	if len(module.openFlags) != 1 || module.openFlags[0] != pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION {
		t.Fatalf("session flags = %v", module.openFlags)
	}
	if gotKDF != pkcs11.CKD_NULL || len(gotSharedData) != 0 || !bytes.Equal(gotPeer, peer[:]) {
		t.Fatalf("ECDH params = kdf %#x shared %x peer %x", gotKDF, gotSharedData, gotPeer)
	}
	if len(module.mechanisms) != 1 || module.mechanisms[0].Mechanism != pkcs11.CKM_ECDH1_DERIVE {
		t.Fatalf("derive mechanisms = %+v", module.mechanisms)
	}
	if module.deriveBase != testPrivateObject {
		t.Fatalf("derive base = %d", module.deriveBase)
	}
	assertTemplate(t, module.findTemplates[0], keyTemplate(pkcs11.CKO_PUBLIC_KEY, 5))
	assertTemplate(t, module.findTemplates[1], keyTemplate(pkcs11.CKO_PRIVATE_KEY, 5))
	assertTemplate(t, module.deriveTemplate, derivedSecretTemplate())
	if len(module.destroyed) != 1 || module.destroyed[0] != testDerivedObject {
		t.Fatalf("destroyed objects = %v", module.destroyed)
	}
	if module.logoutCalls != 1 || module.closeCalls != 1 || module.finalizeCalls != 1 || module.destroyCalls != 1 {
		t.Fatalf("cleanup calls logout=%d close=%d finalize=%d destroy=%d", module.logoutCalls, module.closeCalls, module.finalizeCalls, module.destroyCalls)
	}
}

func TestDeriveWithReadyRunsAfterLoginAndBeforePrivateOperation(t *testing.T) {
	publicKey := bytes32(1)
	shared := bytes32(129)
	module := deriveFake(publicKey, shared)
	backend := fakeBackend(module)
	readyCalls := 0

	got, err := backend.DeriveWithReady(
		context.Background(),
		Target{Serial: testSerial, Slot: "82", PublicKey: publicKey},
		[]byte("654321"),
		bytes32(65),
		func() error {
			readyCalls++
			if module.loginCalls != 1 {
				t.Fatalf("ready ran before successful login: calls=%d", module.loginCalls)
			}
			if len(module.findTemplates) != 2 {
				t.Fatalf("ready ran before private object validation: templates=%d", len(module.findTemplates))
			}
			if len(module.mechanisms) != 0 {
				t.Fatal("ECDH began before ready")
			}
			return nil
		},
	)
	if err != nil || got != shared || readyCalls != 1 {
		t.Fatalf("DeriveWithReady = %x, %v; ready calls=%d", got, err, readyCalls)
	}
}

func TestDeriveWithReadyDoesNotSignalForRejectedPIN(t *testing.T) {
	publicKey := bytes32(1)
	module := deriveFake(publicKey, bytes32(129))
	module.loginError = errors.New("rejected PIN details")
	readyCalls := 0

	got, err := fakeBackend(module).DeriveWithReady(
		context.Background(),
		Target{Serial: testSerial, Slot: "82", PublicKey: publicKey},
		[]byte("654321"),
		bytes32(65),
		func() error {
			readyCalls++
			return nil
		},
	)
	if !errors.Is(err, ErrPINLoginFailed) || got != ([32]byte{}) || readyCalls != 0 {
		t.Fatalf("DeriveWithReady = %x, %v; ready calls=%d", got, err, readyCalls)
	}
	if len(module.mechanisms) != 0 {
		t.Fatal("rejected PIN reached ECDH")
	}
}

func TestDeriveWithReadyFailsClosedBeforePrivateOperation(t *testing.T) {
	publicKey := bytes32(1)
	module := deriveFake(publicKey, bytes32(129))
	const sensitive = "continue pipe private detail"

	got, err := fakeBackend(module).DeriveWithReady(
		context.Background(),
		Target{Serial: testSerial, Slot: "82", PublicKey: publicKey},
		[]byte("654321"),
		bytes32(65),
		func() error { return errors.New(sensitive) },
	)
	if !errors.Is(err, ErrReadyFailed) || got != ([32]byte{}) {
		t.Fatalf("DeriveWithReady = %x, %v", got, err)
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatal("ready failure leaked callback details")
	}
	if len(module.findTemplates) != 2 || len(module.mechanisms) != 0 {
		t.Fatalf("ready failure reached private operation: templates=%d mechanisms=%d", len(module.findTemplates), len(module.mechanisms))
	}
	if module.logoutCalls != 1 || module.closeCalls != 1 || module.finalizeCalls != 1 || module.destroyCalls != 1 {
		t.Fatalf("cleanup calls logout=%d close=%d finalize=%d destroy=%d", module.logoutCalls, module.closeCalls, module.finalizeCalls, module.destroyCalls)
	}
}

func TestDeriveClassifiesFailuresAndDestroysTemporaryObject(t *testing.T) {
	publicKey := bytes32(1)
	shared := bytes32(129)
	tests := []struct {
		name          string
		mutate        func(*fakeModule)
		want          error
		wantDestroyed bool
	}{
		{name: "PIN login", mutate: func(m *fakeModule) { m.loginError = errors.New("bad PIN raw detail") }, want: ErrPINLoginFailed},
		{name: "private missing", mutate: func(m *fakeModule) { m.findResults[2] = nil }, want: ErrTargetMismatch},
		{name: "private duplicate", mutate: func(m *fakeModule) { m.findResults[2] = []pkcs11.ObjectHandle{testPrivateObject, 23} }, want: ErrTargetMismatch},
		{name: "derive", mutate: func(m *fakeModule) { m.deriveError = errors.New("derive raw detail") }, want: ErrDeriveFailed, wantDestroyed: true},
		{name: "read value", mutate: func(m *fakeModule) {
			m.attributeErrors = map[pkcs11.ObjectHandle]error{testDerivedObject: errors.New("attribute raw detail")}
		}, want: ErrDeriveFailed, wantDestroyed: true},
		{name: "destroy", mutate: func(m *fakeModule) { m.destroyError = errors.New("destroy raw detail") }, want: ErrDeriveFailed, wantDestroyed: true},
		{name: "short secret", mutate: func(m *fakeModule) { m.attributes[testDerivedObject][0].Value = []byte{1, 2, 3} }, want: ErrDeriveFailed, wantDestroyed: true},
		{name: "zero secret", mutate: func(m *fakeModule) { m.attributes[testDerivedObject][0].Value = make([]byte, 32) }, want: ErrDeriveFailed, wantDestroyed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module := deriveFake(publicKey, shared)
			test.mutate(module)
			backend := fakeBackend(module)
			got, err := backend.Derive(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey}, []byte("654321"), bytes32(65))
			if !errors.Is(err, test.want) {
				t.Fatalf("derive error = %v, want %v", err, test.want)
			}
			if got != ([32]byte{}) {
				t.Fatal("failed derive returned secret material")
			}
			if test.wantDestroyed && (len(module.destroyed) != 1 || module.destroyed[0] != testDerivedObject) {
				t.Fatalf("destroyed objects = %v", module.destroyed)
			}
			if !test.wantDestroyed && len(module.destroyed) != 0 {
				t.Fatalf("unexpected destroyed objects = %v", module.destroyed)
			}
		})
	}
}

func TestSessionReusesOneLoginForTwoDerives(t *testing.T) {
	publicKey := bytes32(1)
	shared := bytes32(129)
	module := deriveFake(publicKey, shared)
	module.findResults = append(module.findResults,
		[]pkcs11.ObjectHandle{testPublicObject}, nil,
		[]pkcs11.ObjectHandle{testPrivateObject}, nil,
		[]pkcs11.ObjectHandle{testPublicObject}, nil,
		[]pkcs11.ObjectHandle{testPrivateObject}, nil,
	)
	backend := fakeBackend(module)
	session, err := backend.OpenSession(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	pin := []byte("654321")
	if err := session.Login(context.Background(), pin); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pin, make([]byte, len(pin))) {
		t.Fatalf("successful Login did not clear PIN: %x", pin)
	}

	for i, peerStart := range []byte{65, 97} {
		if err := session.Validate(context.Background()); err != nil {
			t.Fatalf("Validate %d: %v", i+1, err)
		}
		got, err := session.Derive(context.Background(), bytes32(peerStart))
		if err != nil || got != shared {
			t.Fatalf("Derive %d = %x, %v", i+1, got, err)
		}
	}
	if module.initializeCalls != 1 || len(module.openFlags) != 1 || module.loginCalls != 1 || module.deriveCalls != 2 {
		t.Fatalf("calls initialize=%d open=%d login=%d derive=%d", module.initializeCalls, len(module.openFlags), module.loginCalls, module.deriveCalls)
	}
	if module.logoutCalls != 0 || module.closeCalls != 0 || module.finalizeCalls != 0 || module.destroyCalls != 0 {
		t.Fatal("successful derives tore down the authenticated session")
	}
	if len(module.destroyed) != 2 || module.destroyed[0] != testDerivedObject || module.destroyed[1] != testDerivedObject {
		t.Fatalf("destroyed objects = %v", module.destroyed)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if module.logoutCalls != 1 || module.closeCalls != 1 || module.finalizeCalls != 1 || module.destroyCalls != 1 {
		t.Fatalf("cleanup calls logout=%d close=%d finalize=%d destroy=%d", module.logoutCalls, module.closeCalls, module.finalizeCalls, module.destroyCalls)
	}
}

func TestSessionLoginClearsPINAfterFailure(t *testing.T) {
	publicKey := bytes32(1)
	module := deriveFake(publicKey, bytes32(129))
	module.loginError = errors.New("rejected PIN private detail")
	backend := fakeBackend(module)
	session, err := backend.OpenSession(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	pin := []byte("654321")
	if err := session.Login(context.Background(), pin); !errors.Is(err, ErrPINLoginFailed) {
		t.Fatalf("Login error = %v", err)
	}
	if !bytes.Equal(pin, make([]byte, len(pin))) {
		t.Fatalf("failed Login did not clear PIN: %x", pin)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRejectsNonConformingKeyPolicies(t *testing.T) {
	publicKey := bytes32(1)
	tests := []struct {
		name       string
		attributes []*pkcs11.Attribute
	}{
		{name: "touch never", attributes: policyAttributes(1, pinPolicyOnce)},
		{name: "touch cached", attributes: policyAttributes(3, pinPolicyOnce)},
		{name: "PIN always", attributes: policyAttributes(touchPolicyAlways, 3)},
		{name: "PIN never", attributes: policyAttributes(touchPolicyAlways, 1)},
		{name: "missing", attributes: policyAttributes(touchPolicyAlways, pinPolicyOnce)[:1]},
		{name: "short", attributes: []*pkcs11.Attribute{
			pkcs11.NewAttribute(ckaYubicoTouchPolicy, nil),
			pkcs11.NewAttribute(ckaYubicoPINPolicy, []byte{pinPolicyOnce}),
		}},
		{name: "wrong type", attributes: []*pkcs11.Attribute{
			pkcs11.NewAttribute(ckaYubicoPINPolicy, []byte{touchPolicyAlways}),
			pkcs11.NewAttribute(ckaYubicoTouchPolicy, []byte{pinPolicyOnce}),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module := deriveFake(publicKey, bytes32(129))
			module.attributes[testPrivateObject] = test.attributes
			got, err := fakeBackend(module).Derive(
				context.Background(),
				Target{Serial: testSerial, Slot: "82", PublicKey: publicKey},
				[]byte("654321"),
				bytes32(65),
			)
			if !errors.Is(err, ErrPolicyMismatch) || got != ([32]byte{}) {
				t.Fatalf("Derive = %x, %v", got, err)
			}
			if module.deriveCalls != 0 {
				t.Fatal("policy mismatch reached ECDH")
			}
			if module.logoutCalls != 1 || module.closeCalls != 1 || module.finalizeCalls != 1 || module.destroyCalls != 1 {
				t.Fatalf("cleanup calls logout=%d close=%d finalize=%d destroy=%d", module.logoutCalls, module.closeCalls, module.finalizeCalls, module.destroyCalls)
			}
		})
	}
}

func TestSessionValidateFailsClosedForInvalidSession(t *testing.T) {
	publicKey := bytes32(1)
	fake := deriveFake(publicKey, bytes32(129))
	backend := fakeBackend(fake)
	session, err := backend.OpenSession(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Login(context.Background(), []byte("654321")); err != nil {
		t.Fatal(err)
	}
	fake.sessionInfoError = errors.New("removed token private detail")
	if err := session.Validate(context.Background()); !errors.Is(err, ErrDeriveFailed) {
		t.Fatalf("Validate error = %v", err)
	}
	if fake.deriveCalls != 0 {
		t.Fatal("invalid session reached ECDH")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCloseAttemptsAllCleanupAfterErrors(t *testing.T) {
	publicKey := bytes32(1)
	fake := deriveFake(publicKey, bytes32(129))
	backend := fakeBackend(fake)
	session, err := backend.OpenSession(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Login(context.Background(), []byte("654321")); err != nil {
		t.Fatal(err)
	}
	fake.logoutError = errors.New("logout private detail")
	fake.closeError = errors.New("close private detail")
	fake.finalizeError = errors.New("finalize private detail")
	if err := session.Close(); !errors.Is(err, ErrDeriveFailed) {
		t.Fatalf("Close error = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
	if fake.logoutCalls != 1 || fake.closeCalls != 1 || fake.finalizeCalls != 1 || fake.destroyCalls != 1 {
		t.Fatalf("cleanup calls logout=%d close=%d finalize=%d destroy=%d", fake.logoutCalls, fake.closeCalls, fake.finalizeCalls, fake.destroyCalls)
	}

	replacement := deriveFake(publicKey, bytes32(129))
	backend.factory = func(string) module { return replacement }
	replacementSession, err := backend.OpenSession(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey})
	if err != nil {
		t.Fatalf("cleanup did not release backend gate: %v", err)
	}
	if err := replacementSession.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQueuedCanceledContextDoesNotEnterPKCS11(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	module := &fakeModule{getSlotListStarted: started, getSlotListRelease: release}
	backend := fakeBackend(module)

	firstDone := make(chan error, 1)
	go func() {
		_, err := backend.ReadPublic(context.Background(), testSerial, "82")
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first operation did not reach PKCS#11")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := backend.ReadPublic(ctx, testSerial, "82"); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued canceled error = %v", err)
	}
	if module.initializeCalls != 1 || module.slotListCalls != 1 {
		t.Fatalf("canceled request entered PKCS#11: initialize=%d slots=%d", module.initializeCalls, module.slotListCalls)
	}
	close(release)
	if err := <-firstDone; !errors.Is(err, ErrNotDetected) {
		t.Fatalf("first operation error = %v", err)
	}
}

func TestCancellationAfterDeriveStillDestroysTemporaryObject(t *testing.T) {
	publicKey := bytes32(1)
	module := deriveFake(publicKey, bytes32(129))
	ctx, cancel := context.WithCancel(context.Background())
	module.deriveHook = cancel
	got, err := fakeBackend(module).Derive(ctx, Target{Serial: testSerial, Slot: "82", PublicKey: publicKey}, []byte("654321"), bytes32(65))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("derive error = %v, want context canceled", err)
	}
	if got != ([32]byte{}) {
		t.Fatal("canceled derive returned secret material")
	}
	if len(module.destroyed) != 1 || module.destroyed[0] != testDerivedObject {
		t.Fatalf("destroyed objects = %v", module.destroyed)
	}
}

func TestPublicErrorsOmitSensitiveInputsAndProviderDetails(t *testing.T) {
	publicKey := bytes32(1)
	peer := bytes32(65)
	shared := bytes32(129)
	pin := []byte("654321-sensitive")
	sensitive := []string{testSerial, string(pin), fmt.Sprintf("%x", publicKey), fmt.Sprintf("%x", peer), fmt.Sprintf("%x", shared)}
	raw := strings.Join(sensitive, " ")

	probeModule := publicFake(publicKey)
	probeModule.attributeErrors = map[pkcs11.ObjectHandle]error{testPublicObject: errors.New(raw)}
	_, probeErr := fakeBackend(probeModule).Probe(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey})
	assertSafeError(t, probeErr, ErrProbeUnavailable, sensitive)

	loginModule := deriveFake(publicKey, shared)
	loginModule.loginError = errors.New(raw)
	_, loginErr := fakeBackend(loginModule).Derive(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey}, pin, peer)
	assertSafeError(t, loginErr, ErrPINLoginFailed, sensitive)

	deriveModule := deriveFake(publicKey, shared)
	deriveModule.deriveError = errors.New(raw)
	_, deriveErr := fakeBackend(deriveModule).Derive(context.Background(), Target{Serial: testSerial, Slot: "82", PublicKey: publicKey}, pin, peer)
	assertSafeError(t, deriveErr, ErrDeriveFailed, sensitive)
}

func TestCloseIsIdempotentAndStopsNewOperations(t *testing.T) {
	backend := fakeBackend(&fakeModule{})
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := backend.Probe(context.Background(), Target{Serial: testSerial, Slot: "82"})
	if result.State != Unavailable || !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("closed probe = %+v, %v", result, err)
	}
}

func fakeBackend(fake *fakeModule) *Backend {
	backend := New("provider-path-must-not-leak")
	backend.factory = func(string) module { return fake }
	return backend
}

func publicFake(publicKey [32]byte) *fakeModule {
	return &fakeModule{
		slots:       []uint{7},
		tokenInfos:  map[uint]pkcs11.TokenInfo{7: {SerialNumber: testSerial}},
		findResults: [][]pkcs11.ObjectHandle{{testPublicObject}, nil},
		attributes: map[pkcs11.ObjectHandle][]*pkcs11.Attribute{
			testPublicObject: {ecPointAttribute(publicKey)},
		},
	}
}

func deriveFake(publicKey [32]byte, shared [32]byte) *fakeModule {
	return &fakeModule{
		slots:       []uint{7},
		tokenInfos:  map[uint]pkcs11.TokenInfo{7: {SerialNumber: testSerial}},
		sessionInfo: pkcs11.SessionInfo{SlotID: 7, State: pkcs11.CKS_RW_USER_FUNCTIONS, Flags: pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION},
		findResults: [][]pkcs11.ObjectHandle{{testPublicObject}, nil, {testPrivateObject}, nil},
		attributes: map[pkcs11.ObjectHandle][]*pkcs11.Attribute{
			testPublicObject:  {ecPointAttribute(publicKey)},
			testPrivateObject: policyAttributes(touchPolicyAlways, pinPolicyOnce),
			testDerivedObject: {pkcs11.NewAttribute(pkcs11.CKA_VALUE, shared[:])},
		},
		deriveObject: testDerivedObject,
	}
}

func ecPointAttribute(publicKey [32]byte) *pkcs11.Attribute {
	value := make([]byte, 34)
	value[0], value[1] = 0x04, 0x20
	copy(value[2:], publicKey[:])
	return pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, value)
}

func policyAttributes(touch, pin byte) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(ckaYubicoTouchPolicy, []byte{touch}),
		pkcs11.NewAttribute(ckaYubicoPINPolicy, []byte{pin}),
	}
}

func bytes32(start byte) [32]byte {
	var value [32]byte
	for i := range value {
		value[i] = start + byte(i)
	}
	return value
}

func assertSafeError(t *testing.T, got error, want error, sensitive []string) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
	for _, value := range sensitive {
		if value != "" && strings.Contains(got.Error(), value) {
			t.Fatalf("error leaked sensitive value: %q", got)
		}
	}
}

func assertTemplate(t *testing.T, got []*pkcs11.Attribute, want []*pkcs11.Attribute) {
	t.Helper()
	defer zeroAttributes(want)
	if len(got) != len(want) {
		t.Fatalf("template length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] == nil || got[i].Type != want[i].Type || !bytes.Equal(got[i].Value, want[i].Value) {
			t.Fatalf("template[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

type fakeModule struct {
	mu sync.Mutex

	initializeError  error
	finalizeError    error
	openError        error
	closeError       error
	sessionInfoError error
	loginError       error
	logoutError      error
	findInitError    error
	findError        error
	findFinalError   error
	deriveError      error
	destroyError     error
	deriveHook       func()

	slots           []uint
	tokenInfos      map[uint]pkcs11.TokenInfo
	tokenInfoErrors map[uint]error
	findResults     [][]pkcs11.ObjectHandle
	attributes      map[pkcs11.ObjectHandle][]*pkcs11.Attribute
	attributeErrors map[pkcs11.ObjectHandle]error
	deriveObject    pkcs11.ObjectHandle
	sessionInfo     pkcs11.SessionInfo

	getSlotListStarted chan struct{}
	getSlotListRelease chan struct{}
	startOnce          sync.Once

	initializeCalls  int
	finalizeCalls    int
	destroyCalls     int
	slotListCalls    int
	closeCalls       int
	loginCalls       int
	sessionInfoCalls int
	logoutCalls      int
	deriveCalls      int
	loginUser        uint
	loginPIN         string
	openFlags        []uint
	findTemplates    [][]*pkcs11.Attribute
	mechanisms       []*pkcs11.Mechanism
	deriveBase       pkcs11.ObjectHandle
	deriveTemplate   []*pkcs11.Attribute
	destroyed        []pkcs11.ObjectHandle
}

func (m *fakeModule) Initialize(...pkcs11.InitializeOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initializeCalls++
	return m.initializeError
}

func (m *fakeModule) Finalize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finalizeCalls++
	return m.finalizeError
}

func (m *fakeModule) Destroy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyCalls++
}

func (m *fakeModule) GetSlotList(tokenPresent bool) ([]uint, error) {
	m.mu.Lock()
	m.slotListCalls++
	m.mu.Unlock()
	if !tokenPresent {
		return nil, errors.New("tokenPresent must be true")
	}
	if m.getSlotListStarted != nil {
		m.startOnce.Do(func() { close(m.getSlotListStarted) })
	}
	if m.getSlotListRelease != nil {
		<-m.getSlotListRelease
	}
	return append([]uint(nil), m.slots...), nil
}

func (m *fakeModule) GetTokenInfo(slot uint) (pkcs11.TokenInfo, error) {
	if err := m.tokenInfoErrors[slot]; err != nil {
		return pkcs11.TokenInfo{}, err
	}
	return m.tokenInfos[slot], nil
}

func (m *fakeModule) OpenSession(_ uint, flags uint) (pkcs11.SessionHandle, error) {
	m.openFlags = append(m.openFlags, flags)
	return 101, m.openError
}

func (m *fakeModule) CloseSession(pkcs11.SessionHandle) error {
	m.closeCalls++
	return m.closeError
}

func (m *fakeModule) GetSessionInfo(pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	m.sessionInfoCalls++
	return m.sessionInfo, m.sessionInfoError
}

func (m *fakeModule) LoginBytes(_ pkcs11.SessionHandle, user uint, pin []byte) error {
	m.loginCalls++
	m.loginUser = user
	m.loginPIN = string(pin)
	return m.loginError
}

func (m *fakeModule) Logout(pkcs11.SessionHandle) error {
	m.logoutCalls++
	return m.logoutError
}

func (m *fakeModule) FindObjectsInit(_ pkcs11.SessionHandle, template []*pkcs11.Attribute) error {
	m.findTemplates = append(m.findTemplates, cloneAttributes(template))
	return m.findInitError
}

func (m *fakeModule) FindObjects(_ pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	if m.findError != nil {
		return nil, false, m.findError
	}
	if len(m.findResults) == 0 {
		return nil, false, nil
	}
	objects := append([]pkcs11.ObjectHandle(nil), m.findResults[0]...)
	m.findResults = m.findResults[1:]
	if len(objects) > max {
		objects = objects[:max]
	}
	return objects, false, nil
}

func (m *fakeModule) FindObjectsFinal(pkcs11.SessionHandle) error {
	return m.findFinalError
}

func (m *fakeModule) GetAttributeValue(_ pkcs11.SessionHandle, object pkcs11.ObjectHandle, _ []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if err := m.attributeErrors[object]; err != nil {
		return nil, err
	}
	return cloneAttributes(m.attributes[object]), nil
}

func (m *fakeModule) DeriveKey(_ pkcs11.SessionHandle, mechanisms []*pkcs11.Mechanism, base pkcs11.ObjectHandle, template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	m.deriveCalls++
	m.mechanisms = append([]*pkcs11.Mechanism(nil), mechanisms...)
	m.deriveBase = base
	m.deriveTemplate = cloneAttributes(template)
	if m.deriveHook != nil {
		m.deriveHook()
	}
	return m.deriveObject, m.deriveError
}

func (m *fakeModule) DestroyObject(_ pkcs11.SessionHandle, object pkcs11.ObjectHandle) error {
	m.destroyed = append(m.destroyed, object)
	return m.destroyError
}

func cloneAttributes(attributes []*pkcs11.Attribute) []*pkcs11.Attribute {
	cloned := make([]*pkcs11.Attribute, len(attributes))
	for i, attribute := range attributes {
		if attribute != nil {
			cloned[i] = &pkcs11.Attribute{Type: attribute.Type, Value: append([]byte(nil), attribute.Value...)}
		}
	}
	return cloned
}
