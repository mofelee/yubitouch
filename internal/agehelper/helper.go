package agehelper

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"path/filepath"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/buildinfo"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/pin"
)

const helperFailureExitCode = 4

type helperDependencies struct {
	loadConfig       func(string, string) (config.Config, error)
	resolvePIN       func(context.Context, config.Config) ([]byte, error)
	deriveHardware   func(context.Context, config.Config, agehardware.Target, []byte, [32]byte, func() error) ([32]byte, error)
	resolveRecovery  func(context.Context, string, string) (string, error)
	disableCoreDump  func() error
	verifyParent     func() error
	watchParentDeath func(func(string) string) (func(), error)
	openContinue     func(func(string) string) (io.ReadCloser, error)
}

func productionHelperDependencies() helperDependencies {
	return helperDependencies{
		loadConfig: config.Load,
		resolvePIN: pin.Resolve,
		deriveHardware: func(ctx context.Context, cfg config.Config, target agehardware.Target, pinValue []byte, peer [32]byte, ready func() error) ([32]byte, error) {
			backend := agehardware.New(cfg.YKCS11Path)
			defer backend.Close()
			return backend.DeriveWithReady(ctx, target, pinValue, peer, ready)
		},
		resolveRecovery:  resolveRecoveryIdentity,
		disableCoreDump:  disableCoreDumps,
		verifyParent:     verifyParentProcess,
		watchParentDeath: startParentLifetimeWatch,
		openContinue:     openHardwareContinue,
	}
}

// RunInternalFromEnvironment runs exactly one age private-key operation when
// the internal mode variable is present. The caller must invoke it before any
// normal command parsing. It never writes diagnostics or raw errors.
func RunInternalFromEnvironment(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	getenv func(string) string,
	home string,
) (handled bool, exitCode int) {
	return runInternal(ctx, stdin, stdout, getenv, home, productionHelperDependencies())
}

func runInternal(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	getenv func(string) string,
	home string,
	deps helperDependencies,
) (bool, int) {
	if getenv == nil {
		return false, 0
	}
	rawMode := getenv(internalModeEnvironment)
	if rawMode == "" {
		return false, 0
	}
	mode, valid := parseMode(rawMode)
	if !valid {
		return true, writeHelperError(stdout, ErrorInvalidRequest)
	}
	if deps.disableCoreDump == nil || deps.disableCoreDump() != nil {
		return true, writeHelperError(stdout, ErrorHelper)
	}
	if deps.verifyParent == nil || deps.verifyParent() != nil {
		return true, writeHelperError(stdout, ErrorHelper)
	}
	if deps.watchParentDeath == nil {
		return true, writeHelperError(stdout, ErrorHelper)
	}
	stopParentWatch, err := deps.watchParentDeath(getenv)
	if err != nil || stopParentWatch == nil {
		return true, writeHelperError(stdout, ErrorHelper)
	}
	defer stopParentWatch()
	if ctx == nil {
		ctx = context.Background()
	}
	var continueReader io.ReadCloser
	if mode == ModeHardware {
		if deps.openContinue == nil {
			return true, writeHelperError(stdout, ErrorHelper)
		}
		continueReader, err = deps.openContinue(getenv)
		if err != nil || continueReader == nil {
			return true, writeHelperError(stdout, ErrorHelper)
		}
		defer continueReader.Close()
	} else if getenv(hardwareContinueEnvironment) != "" {
		return true, writeHelperError(stdout, ErrorHelper)
	}

	configValue := getenv("YUBITOUCH_CONFIG")
	if strings.TrimSpace(configValue) == "" || strings.TrimSpace(configValue) != configValue {
		return true, writeHelperError(stdout, ErrorConfiguration)
	}
	configPath := config.PathFromEnvironment(home, getenv)
	if !filepath.IsAbs(configPath) {
		return true, writeHelperError(stdout, ErrorConfiguration)
	}

	encoded, err := readFrame(stdin, maxRequestFrame)
	if err != nil {
		return true, writeHelperError(stdout, ErrorInvalidRequest)
	}
	defer clear(encoded)
	if err := ensureEOF(stdin); err != nil {
		return true, writeHelperError(stdout, ErrorInvalidRequest)
	}
	request, err := unmarshalRequest(encoded, mode)
	if err != nil {
		return true, writeHelperError(stdout, ErrorInvalidRequest)
	}

	if deps.loadConfig == nil {
		return true, writeHelperError(stdout, ErrorConfiguration)
	}
	cfg, err := deps.loadConfig(configPath, home)
	if err != nil || cfg.Age == nil {
		return true, writeHelperError(stdout, ErrorConfiguration)
	}
	if deps.verifyParent() != nil {
		return true, writeHelperError(stdout, ErrorHelper)
	}
	fileKey, class := executeRequest(ctx, mode, request, cfg, stdout, continueReader, deps)
	if class != "" {
		secureClear(fileKey)
		return true, writeHelperError(stdout, class)
	}
	defer secureClear(fileKey)
	encodedResponse, err := marshalResponse(fileKey, "")
	if err != nil {
		return true, writeHelperError(stdout, ErrorHelper)
	}
	defer clear(encodedResponse)
	if err := writeFrame(stdout, encodedResponse, maxResponseFrame); err != nil {
		return true, helperFailureExitCode
	}
	return true, 0
}

func executeRequest(
	ctx context.Context,
	mode Mode,
	request Request,
	cfg config.Config,
	stdout io.Writer,
	continueReader io.Reader,
	deps helperDependencies,
) ([]byte, ErrorClass) {
	if err := ctx.Err(); err != nil {
		return nil, contextClass(err)
	}
	hardwarePublic, ok := configuredHardwarePublicKey(cfg)
	if !ok {
		return nil, ErrorConfiguration
	}
	defer clear(hardwarePublic[:])

	switch mode {
	case ModeHardware:
		return executeHardware(ctx, request.Envelope, cfg, hardwarePublic, stdout, continueReader, deps)
	case ModeRecovery:
		return executeRecovery(ctx, request.Envelope, cfg, hardwarePublic, deps)
	default:
		return nil, ErrorInvalidRequest
	}
}

func executeHardware(
	ctx context.Context,
	envelope ageprofile.Envelope,
	cfg config.Config,
	hardwarePublic ageprofile.PublicKey,
	stdout io.Writer,
	continueReader io.Reader,
	deps helperDependencies,
) ([]byte, ErrorClass) {
	expected, err := ageprofile.NewRecipient(hardwarePublic, nil)
	if err != nil || envelope.Path != ageprofile.PathHardware ||
		envelope.ProfileID != expected.ProfileID() || envelope.KeyID != expected.Hardware().ID {
		return nil, ErrorHardwareMismatch
	}
	if deps.resolvePIN == nil || deps.deriveHardware == nil {
		return nil, ErrorHardware
	}
	pinValue, err := deps.resolvePIN(ctx, cfg)
	if err != nil || len(pinValue) == 0 {
		secureClear(pinValue)
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextClass(contextErr)
		}
		return nil, ErrorPINProvider
	}
	defer secureClear(pinValue)
	target := agehardware.Target{
		Serial:    cfg.Age.Serial,
		Slot:      cfg.Age.Slot,
		PublicKey: [32]byte(hardwarePublic),
	}
	readyAttempted := false
	readyCompleted := false
	readyInvalid := false
	readyForTouch := func() error {
		if readyAttempted {
			readyInvalid = true
			return errors.New("age helper readiness callback was repeated")
		}
		readyAttempted = true
		if err := ctx.Err(); err != nil {
			readyInvalid = true
			return err
		}
		ready, err := marshalReady()
		if err != nil {
			readyInvalid = true
			return errors.New("age helper readiness frame is unavailable")
		}
		defer clear(ready)
		if err := writeFrame(stdout, ready, maxResponseFrame); err != nil {
			readyInvalid = true
			return errors.New("age helper readiness frame cannot be written")
		}
		if err := readHardwareContinue(continueReader); err != nil {
			readyInvalid = true
			return errors.New("age helper continue signal is invalid")
		}
		if deps.verifyParent == nil || deps.verifyParent() != nil {
			readyInvalid = true
			return errors.New("age helper parent changed before hardware access")
		}
		readyCompleted = true
		return nil
	}
	sharedSecret, err := deps.deriveHardware(ctx, cfg, target, pinValue, [32]byte(envelope.EphemeralPublicKey), readyForTouch)
	secureLock(sharedSecret[:])
	defer secureClear(sharedSecret[:])
	if readyInvalid {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextClass(contextErr)
		}
		return nil, ErrorHelper
	}
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, contextClass(err)
		case errors.Is(err, agehardware.ErrTargetMismatch), errors.Is(err, agehardware.ErrNotDetected):
			return nil, ErrorHardwareMismatch
		case errors.Is(err, agehardware.ErrPINLoginFailed):
			return nil, ErrorHardwarePIN
		default:
			return nil, ErrorHardware
		}
	}
	if !readyCompleted {
		return nil, ErrorHelper
	}
	fileKey, err := ageprofile.UnwrapWithSharedSecret(envelope, hardwarePublic, sharedSecret[:])
	if err != nil || len(fileKey) != fileKeySize {
		secureClear(fileKey)
		return nil, ErrorUnwrap
	}
	secureLock(fileKey)
	return fileKey, ""
}

func executeRecovery(
	ctx context.Context,
	envelope ageprofile.Envelope,
	cfg config.Config,
	hardwarePublic ageprofile.PublicKey,
	deps helperDependencies,
) ([]byte, ErrorClass) {
	if cfg.Age.Recovery == nil || cfg.Age.Recovery.Provider != "1password" || deps.resolveRecovery == nil {
		return nil, ErrorRecoveryUnavailable
	}
	recoveryPublic, err := ageprofile.ParseNativeRecipient(cfg.Age.Recovery.Recipient)
	if err != nil {
		return nil, ErrorConfiguration
	}
	defer clear(recoveryPublic[:])
	expected, err := ageprofile.NewRecipient(hardwarePublic, &recoveryPublic)
	if err != nil {
		return nil, ErrorConfiguration
	}
	recoveryKey, ok := expected.Recovery()
	if !ok || envelope.Path != ageprofile.PathRecovery ||
		envelope.ProfileID != expected.ProfileID() || envelope.KeyID != recoveryKey.ID {
		return nil, ErrorRecoveryMismatch
	}

	identity, err := deps.resolveRecovery(ctx, cfg.OnePasswordAccount, cfg.Age.Recovery.IdentityRef)
	if err != nil || len(identity) != 74 {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextClass(contextErr)
		}
		return nil, ErrorRecoveryUnavailable
	}
	// The 1Password SDK returns an immutable Go string, which cannot be
	// reliably zeroed. This one-shot process exits immediately after the copy
	// below is parsed and cleared.
	identityBytes := []byte(identity)
	secureLock(identityBytes)
	defer secureClear(identityBytes)
	privateKey, err := ageprofile.ParseNativeIdentity(string(identityBytes))
	if err != nil {
		return nil, ErrorRecoveryUnavailable
	}
	publicBytes := privateKey.PublicKey().Bytes()
	defer clear(publicBytes)
	if len(publicBytes) != len(recoveryPublic) || subtle.ConstantTimeCompare(publicBytes, recoveryPublic[:]) != 1 {
		return nil, ErrorRecoveryMismatch
	}
	fileKey, err := ageprofile.UnwrapWithPrivateKey(envelope, privateKey)
	if err != nil || len(fileKey) != fileKeySize {
		secureClear(fileKey)
		return nil, ErrorUnwrap
	}
	secureLock(fileKey)
	return fileKey, ""
}

func configuredHardwarePublicKey(cfg config.Config) (ageprofile.PublicKey, bool) {
	var publicKey ageprofile.PublicKey
	if cfg.Age == nil || cfg.Age.PublicKey == "" {
		return publicKey, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cfg.Age.PublicKey)
	if err != nil || len(decoded) != len(publicKey) || base64.RawURLEncoding.EncodeToString(decoded) != cfg.Age.PublicKey {
		clear(decoded)
		return publicKey, false
	}
	copy(publicKey[:], decoded)
	clear(decoded)
	if _, err := ageprofile.NewRecipient(publicKey, nil); err != nil {
		clear(publicKey[:])
		return ageprofile.PublicKey{}, false
	}
	return publicKey, true
}

func resolveRecoveryIdentity(ctx context.Context, account, reference string) (string, error) {
	if err := onepassword.Secrets.ValidateSecretReference(ctx, reference); err != nil {
		return "", err
	}
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("YubiTouch", buildinfo.Version),
	)
	if err != nil {
		return "", err
	}
	return client.Secrets().Resolve(ctx, reference)
}

func contextClass(err error) ErrorClass {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorTimeout
	}
	return ErrorCanceled
}

func writeHelperError(stdout io.Writer, class ErrorClass) int {
	encoded, err := marshalResponse(nil, class)
	if err != nil {
		return helperFailureExitCode
	}
	defer clear(encoded)
	if err := writeFrame(stdout, encoded, maxResponseFrame); err != nil {
		return helperFailureExitCode
	}
	return helperFailureExitCode
}
