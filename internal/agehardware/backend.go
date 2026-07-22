package agehardware

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

const ckkECMontgomery uint = 0x00000041

var (
	ErrNotDetected      = errors.New("target YubiKey not detected")
	ErrTargetMismatch   = errors.New("YubiKey target mismatch")
	ErrProbeUnavailable = errors.New("YubiKey probe unavailable")
	ErrPINLoginFailed   = errors.New("YubiKey PIN login failed")
	ErrReadyFailed      = errors.New("YubiKey operation was not authorized to continue")
	ErrDeriveFailed     = errors.New("YubiKey key derivation failed")
)

type ProbeState string

const (
	Connected   ProbeState = "connected"
	NotDetected ProbeState = "not_detected"
	Mismatch    ProbeState = "mismatch"
	Unavailable ProbeState = "unavailable"
)

type ProbeResult struct {
	State ProbeState
}

type Target struct {
	Serial    string
	Slot      string
	PublicKey [32]byte
}

type module interface {
	Initialize(...pkcs11.InitializeOption) error
	Finalize() error
	Destroy()
	GetSlotList(bool) ([]uint, error)
	GetTokenInfo(uint) (pkcs11.TokenInfo, error)
	OpenSession(uint, uint) (pkcs11.SessionHandle, error)
	CloseSession(pkcs11.SessionHandle) error
	Login(pkcs11.SessionHandle, uint, string) error
	Logout(pkcs11.SessionHandle) error
	FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error
	FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(pkcs11.SessionHandle) error
	GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error
}

type moduleFactory func(string) module

type Backend struct {
	provider string
	factory  moduleFactory
	gate     chan struct{}
	closed   chan struct{}
	close    sync.Once

	newECDHParams func(uint, []byte, []byte) *pkcs11.ECDH1DeriveParams
}

func New(provider string) *Backend {
	return &Backend{
		provider: provider,
		factory: func(path string) module {
			return pkcs11.New(path)
		},
		gate:          make(chan struct{}, 1),
		closed:        make(chan struct{}),
		newECDHParams: pkcs11.NewECDH1DeriveParams,
	}
}

func (b *Backend) Close() error {
	if b == nil {
		return nil
	}
	b.close.Do(func() { close(b.closed) })
	return nil
}

func (b *Backend) Probe(ctx context.Context, target Target) (ProbeResult, error) {
	publicKey, err := b.ReadPublic(ctx, target.Serial, target.Slot)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotDetected):
			return ProbeResult{State: NotDetected}, nil
		case errors.Is(err, ErrTargetMismatch):
			return ProbeResult{State: Mismatch}, ErrTargetMismatch
		default:
			return ProbeResult{State: Unavailable}, err
		}
	}
	defer zero(publicKey[:])
	if subtle.ConstantTimeCompare(publicKey[:], target.PublicKey[:]) != 1 {
		return ProbeResult{State: Mismatch}, ErrTargetMismatch
	}
	return ProbeResult{State: Connected}, nil
}

// ReadPublic reads the unique X25519 public key in a configured PIV slot. It
// deliberately uses a read-only session and never logs in to the token.
func (b *Backend) ReadPublic(ctx context.Context, serial string, slot string) ([32]byte, error) {
	var publicKey [32]byte
	slotID, err := pivSlotID(slot)
	if err != nil || !validSerial(serial) {
		return publicKey, ErrTargetMismatch
	}
	if err := b.acquire(ctx); err != nil {
		return publicKey, classifyProbeError(err)
	}
	defer b.release()

	return b.readPublic(ctx, serial, slotID)
}

func (b *Backend) readPublic(ctx context.Context, serial string, slotID byte) (publicKey [32]byte, err error) {
	m, err := b.openModule(ctx)
	if err != nil {
		return publicKey, classifyProbeError(err)
	}
	defer m.Destroy()
	defer func() {
		if finalizeErr := m.Finalize(); finalizeErr != nil {
			zero(publicKey[:])
			err = ErrProbeUnavailable
		}
	}()

	tokenSlot, locateErr := locateToken(ctx, m, serial)
	if locateErr != nil {
		return publicKey, classifyProbeError(locateErr)
	}

	if contextErr := ctx.Err(); contextErr != nil {
		return publicKey, contextErr
	}
	session, callErr := m.OpenSession(tokenSlot, pkcs11.CKF_SERIAL_SESSION)
	contextErr := ctx.Err()
	if callErr != nil {
		if contextErr != nil {
			return publicKey, contextErr
		}
		return publicKey, classifyProbeError(callErr)
	}
	defer func() {
		if closeErr := m.CloseSession(session); closeErr != nil {
			zero(publicKey[:])
			err = ErrProbeUnavailable
		}
	}()
	if contextErr != nil {
		return publicKey, contextErr
	}

	object, unique, findErr := findUnique(ctx, m, session, keyTemplate(pkcs11.CKO_PUBLIC_KEY, slotID))
	if findErr != nil {
		return publicKey, classifyProbeError(findErr)
	}
	if !unique {
		return publicKey, ErrTargetMismatch
	}

	attributes, attrErr := callValue(ctx, func() ([]*pkcs11.Attribute, error) {
		return m.GetAttributeValue(session, object, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
	})
	if attrErr != nil {
		zeroAttributes(attributes)
		return publicKey, classifyProbeError(attrErr)
	}
	defer zeroAttributes(attributes)
	if len(attributes) != 1 || attributes[0] == nil || attributes[0].Type != pkcs11.CKA_EC_POINT ||
		len(attributes[0].Value) != 34 || attributes[0].Value[0] != 0x04 || attributes[0].Value[1] != 0x20 {
		return publicKey, ErrTargetMismatch
	}
	copy(publicKey[:], attributes[0].Value[2:])
	return publicKey, nil
}

func (b *Backend) Derive(ctx context.Context, target Target, pin []byte, peer [32]byte) (secret [32]byte, err error) {
	return b.derive(ctx, target, pin, peer, nil)
}

// DeriveWithReady invokes ready exactly once after the target public key,
// successful PIN login, and unique private object are verified, but before
// CKM_ECDH1_DERIVE begins. A non-nil callback is required so callers can
// synchronize user-facing touch state with the actual hardware operation.
func (b *Backend) DeriveWithReady(
	ctx context.Context,
	target Target,
	pin []byte,
	peer [32]byte,
	ready func() error,
) (secret [32]byte, err error) {
	if ready == nil {
		return secret, ErrReadyFailed
	}
	return b.derive(ctx, target, pin, peer, ready)
}

func (b *Backend) derive(
	ctx context.Context,
	target Target,
	pin []byte,
	peer [32]byte,
	ready func() error,
) (secret [32]byte, err error) {
	slotID, validationErr := pivSlotID(target.Slot)
	if validationErr != nil || !validSerial(target.Serial) {
		return secret, ErrTargetMismatch
	}
	if acquireErr := b.acquire(ctx); acquireErr != nil {
		return secret, classifyDeriveError(acquireErr)
	}
	defer b.release()

	pinCopy := append([]byte(nil), pin...)
	peerCopy := append([]byte(nil), peer[:]...)
	defer zero(pinCopy)
	defer zero(peerCopy)
	defer zero(peer[:])

	m, moduleErr := b.openModule(ctx)
	if moduleErr != nil {
		return secret, classifyDeriveError(moduleErr)
	}
	defer m.Destroy()
	defer func() {
		if finalizeErr := m.Finalize(); finalizeErr != nil {
			zero(secret[:])
			err = ErrDeriveFailed
		}
	}()

	tokenSlot, locateErr := locateToken(ctx, m, target.Serial)
	if locateErr != nil {
		if isContextError(locateErr) {
			return secret, locateErr
		}
		if errors.Is(locateErr, ErrNotDetected) || errors.Is(locateErr, ErrTargetMismatch) {
			return secret, ErrTargetMismatch
		}
		return secret, ErrDeriveFailed
	}

	if contextErr := ctx.Err(); contextErr != nil {
		return secret, contextErr
	}
	session, sessionErr := m.OpenSession(tokenSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	contextErr := ctx.Err()
	if sessionErr != nil {
		if contextErr != nil {
			return secret, contextErr
		}
		return secret, classifyDeriveError(sessionErr)
	}
	defer func() {
		if closeErr := m.CloseSession(session); closeErr != nil {
			zero(secret[:])
			err = ErrDeriveFailed
		}
	}()
	if contextErr != nil {
		return secret, contextErr
	}

	publicObject, unique, findErr := findUnique(ctx, m, session, keyTemplate(pkcs11.CKO_PUBLIC_KEY, slotID))
	if findErr != nil {
		return secret, classifyDeriveError(findErr)
	}
	if !unique {
		return secret, ErrTargetMismatch
	}
	attributes, attrErr := callValue(ctx, func() ([]*pkcs11.Attribute, error) {
		return m.GetAttributeValue(session, publicObject, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
	})
	if attrErr != nil {
		zeroAttributes(attributes)
		return secret, classifyDeriveError(attrErr)
	}
	if !matchesPublicKey(attributes, target.PublicKey) {
		zeroAttributes(attributes)
		return secret, ErrTargetMismatch
	}
	zeroAttributes(attributes)

	if contextErr := ctx.Err(); contextErr != nil {
		return secret, contextErr
	}
	loginErr := login(m, session, pinCopy)
	contextErr = ctx.Err()
	if loginErr == nil {
		defer func() {
			if logoutErr := m.Logout(session); logoutErr != nil {
				zero(secret[:])
				err = ErrDeriveFailed
			}
		}()
	}
	if contextErr != nil {
		return secret, contextErr
	}
	if loginErr != nil {
		return secret, ErrPINLoginFailed
	}
	privateObject, unique, findErr := findUnique(ctx, m, session, keyTemplate(pkcs11.CKO_PRIVATE_KEY, slotID))
	if findErr != nil {
		return secret, classifyDeriveError(findErr)
	}
	if !unique {
		return secret, ErrTargetMismatch
	}
	if ready != nil {
		if readyErr := ready(); readyErr != nil {
			if isContextError(readyErr) {
				return secret, readyErr
			}
			return secret, ErrReadyFailed
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return secret, contextErr
		}
	}

	template := derivedSecretTemplate()
	defer zeroAttributes(template)
	params := b.newECDHParams(pkcs11.CKD_NULL, nil, peerCopy)
	mechanisms := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)}
	if contextErr := ctx.Err(); contextErr != nil {
		return secret, contextErr
	}
	derivedObject, deriveErr := m.DeriveKey(session, mechanisms, privateObject, template)
	contextErr = ctx.Err()
	derived := deriveErr == nil || derivedObject != 0
	if derived {
		defer func() {
			if destroyErr := m.DestroyObject(session, derivedObject); destroyErr != nil {
				zero(secret[:])
				err = ErrDeriveFailed
			}
		}()
	}
	if contextErr != nil {
		return secret, contextErr
	}
	if deriveErr != nil {
		return secret, classifyDeriveError(deriveErr)
	}

	valueAttributes, valueErr := callValue(ctx, func() ([]*pkcs11.Attribute, error) {
		return m.GetAttributeValue(session, derivedObject, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	})
	if valueErr != nil {
		zeroAttributes(valueAttributes)
		return secret, classifyDeriveError(valueErr)
	}
	defer zeroAttributes(valueAttributes)
	if len(valueAttributes) != 1 || valueAttributes[0] == nil || valueAttributes[0].Type != pkcs11.CKA_VALUE || len(valueAttributes[0].Value) != len(secret) {
		return secret, ErrDeriveFailed
	}
	copy(secret[:], valueAttributes[0].Value)
	var zeroSecret [32]byte
	if subtle.ConstantTimeCompare(secret[:], zeroSecret[:]) == 1 {
		zero(secret[:])
		return secret, ErrDeriveFailed
	}
	return secret, nil
}

func (b *Backend) openModule(ctx context.Context) (module, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b == nil || b.factory == nil {
		return nil, ErrProbeUnavailable
	}
	m := b.factory(b.provider)
	if m == nil {
		return nil, ErrProbeUnavailable
	}
	if err := callErr(ctx, func() error { return m.Initialize() }); err != nil {
		m.Finalize()
		m.Destroy()
		return nil, err
	}
	return m, nil
}

func (b *Backend) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.gate == nil || b.closed == nil {
		return ErrProbeUnavailable
	}
	select {
	case b.gate <- struct{}{}:
	case <-b.closed:
		return ErrProbeUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		b.release()
		return err
	}
	select {
	case <-b.closed:
		b.release()
		return ErrProbeUnavailable
	default:
		return nil
	}
}

func (b *Backend) release() {
	<-b.gate
}

func locateToken(ctx context.Context, m module, serial string) (uint, error) {
	slots, err := callValue(ctx, func() ([]uint, error) { return m.GetSlotList(true) })
	if err != nil {
		return 0, err
	}
	if len(slots) == 0 {
		return 0, ErrNotDetected
	}
	var target uint
	found := false
	for _, slot := range slots {
		info, infoErr := callValue(ctx, func() (pkcs11.TokenInfo, error) { return m.GetTokenInfo(slot) })
		if infoErr != nil {
			return 0, infoErr
		}
		if info.SerialNumber == serial {
			if found {
				return 0, ErrTargetMismatch
			}
			target = slot
			found = true
		}
	}
	if !found {
		return 0, ErrTargetMismatch
	}
	return target, nil
}

func findUnique(ctx context.Context, m module, session pkcs11.SessionHandle, template []*pkcs11.Attribute) (object pkcs11.ObjectHandle, unique bool, err error) {
	defer zeroAttributes(template)
	if contextErr := ctx.Err(); contextErr != nil {
		return 0, false, contextErr
	}
	initErr := m.FindObjectsInit(session, template)
	contextErr := ctx.Err()
	if initErr != nil {
		if contextErr != nil {
			return 0, false, contextErr
		}
		return 0, false, initErr
	}
	finalized := false
	defer func() {
		if finalized {
			return
		}
		finalErr := m.FindObjectsFinal(session)
		if err == nil {
			if contextErr := ctx.Err(); contextErr != nil {
				err = contextErr
			} else if finalErr != nil {
				err = finalErr
			}
		}
	}()
	if contextErr != nil {
		return 0, false, contextErr
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	objects, _, findErr := m.FindObjects(session, 2)
	if contextErr := ctx.Err(); contextErr != nil {
		findErr = contextErr
	}
	var additional []pkcs11.ObjectHandle
	if findErr == nil && len(objects) == 1 {
		additional, _, findErr = m.FindObjects(session, 1)
		if contextErr := ctx.Err(); contextErr != nil {
			findErr = contextErr
		}
	}
	contextBeforeFinal := ctx.Err()
	finalErr := m.FindObjectsFinal(session)
	finalized = true
	if findErr != nil {
		return 0, false, findErr
	}
	if contextBeforeFinal != nil {
		return 0, false, contextBeforeFinal
	}
	if contextAfterFinal := ctx.Err(); contextAfterFinal != nil {
		return 0, false, contextAfterFinal
	}
	if finalErr != nil {
		return 0, false, finalErr
	}
	if len(objects) != 1 || len(additional) != 0 {
		return 0, false, nil
	}
	return objects[0], true, nil
}

func keyTemplate(class uint, slotID byte) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ckkECMontgomery),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{slotID}),
	}
}

func derivedSecretTemplate() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	}
}

func matchesPublicKey(attributes []*pkcs11.Attribute, expected [32]byte) bool {
	if len(attributes) != 1 || attributes[0] == nil || attributes[0].Type != pkcs11.CKA_EC_POINT ||
		len(attributes[0].Value) != 34 || attributes[0].Value[0] != 0x04 || attributes[0].Value[1] != 0x20 {
		return false
	}
	return subtle.ConstantTimeCompare(attributes[0].Value[2:], expected[:]) == 1
}

func pivSlotID(slot string) (byte, error) {
	if len(slot) != 2 {
		return 0, ErrTargetMismatch
	}
	switch strings.ToLower(slot) {
	case "9a":
		return 1, nil
	case "9e":
		return 2, nil
	case "9c":
		return 3, nil
	case "9d":
		return 4, nil
	}
	value, err := strconv.ParseUint(slot, 16, 8)
	if err != nil || value < 0x82 || value > 0x95 {
		return 0, ErrTargetMismatch
	}
	return byte(value-0x82) + 5, nil
}

func validSerial(serial string) bool {
	value, err := strconv.ParseUint(serial, 10, 32)
	return err == nil && value != 0 && strconv.FormatUint(value, 10) == serial
}

func login(m module, session pkcs11.SessionHandle, pin []byte) error {
	// miekg/pkcs11 requires an immutable string. Keep that unavoidable copy in
	// this small scope; the caller still clears all mutable PIN buffers.
	return m.Login(session, pkcs11.CKU_USER, string(pin))
}

func callErr(ctx context.Context, call func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := call()
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func callValue[T any](ctx context.Context, call func() (T, error)) (T, error) {
	var zeroValue T
	if err := ctx.Err(); err != nil {
		return zeroValue, err
	}
	value, err := call()
	if contextErr := ctx.Err(); contextErr != nil {
		return value, contextErr
	}
	return value, err
}

func classifyProbeError(err error) error {
	if isContextError(err) || errors.Is(err, ErrNotDetected) || errors.Is(err, ErrTargetMismatch) || errors.Is(err, ErrProbeUnavailable) {
		return err
	}
	return ErrProbeUnavailable
}

func classifyDeriveError(err error) error {
	if isContextError(err) || errors.Is(err, ErrTargetMismatch) || errors.Is(err, ErrPINLoginFailed) || errors.Is(err, ErrDeriveFailed) {
		return err
	}
	return ErrDeriveFailed
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func zeroAttributes(attributes []*pkcs11.Attribute) {
	for _, attribute := range attributes {
		if attribute != nil {
			zero(attribute.Value)
		}
	}
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
