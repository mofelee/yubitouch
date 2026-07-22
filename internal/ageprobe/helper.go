package ageprobe

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"path/filepath"
	"strings"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
)

// publicBackend intentionally exposes no login or private-key operation.
type publicBackend interface {
	ReadPublic(context.Context, string, string) ([32]byte, error)
	Probe(context.Context, agehardware.Target) (agehardware.ProbeResult, error)
	Close() error
}

type helperDependencies struct {
	loadConfig       func(string, string) (config.Config, error)
	newBackend       func(string) publicBackend
	watchParentDeath func(func(string) string) (func(), error)
}

func productionHelperDependencies() helperDependencies {
	return helperDependencies{
		loadConfig: config.Load,
		newBackend: func(provider string) publicBackend {
			return agehardware.New(provider)
		},
		watchParentDeath: startParentLifetimeWatch,
	}
}

// RunInternalFromEnvironment handles one read-only age hardware operation.
// It emits only a framed response and never writes diagnostics.
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
	if getenv == nil || getenv(internalModeEnvironment) == "" {
		return false, 0
	}
	if getenv(internalModeEnvironment) != "1" {
		return true, writeHelperFailure(stdout, ErrorInvalidRequest)
	}
	if deps.watchParentDeath == nil {
		return true, writeHelperFailure(stdout, ErrorHelper)
	}
	stopParentWatch, err := deps.watchParentDeath(getenv)
	if err != nil || stopParentWatch == nil {
		return true, writeHelperFailure(stdout, ErrorHelper)
	}
	defer stopParentWatch()
	if ctx == nil {
		ctx = context.Background()
	}

	configValue := getenv("YUBITOUCH_CONFIG")
	if strings.TrimSpace(configValue) == "" || strings.TrimSpace(configValue) != configValue {
		return true, writeHelperFailure(stdout, ErrorConfiguration)
	}
	configPath := config.PathFromEnvironment(home, getenv)
	if !filepath.IsAbs(configPath) {
		return true, writeHelperFailure(stdout, ErrorConfiguration)
	}

	encoded, err := readFrame(stdin, maxRequestFrame)
	if err != nil {
		return true, writeHelperFailure(stdout, ErrorInvalidRequest)
	}
	defer clear(encoded)
	if ensureEOF(stdin) != nil {
		return true, writeHelperFailure(stdout, ErrorInvalidRequest)
	}
	request, err := unmarshalRequest(encoded)
	if err != nil {
		return true, writeHelperFailure(stdout, ErrorInvalidRequest)
	}
	if deps.loadConfig == nil || deps.newBackend == nil {
		return true, writeHelperFailure(stdout, ErrorConfiguration)
	}
	cfg, err := deps.loadConfig(configPath, home)
	if err != nil || cfg.Age == nil {
		return true, writeHelperFailure(stdout, ErrorConfiguration)
	}
	if request.Serial != cfg.Age.Serial || request.Slot != cfg.Age.Slot {
		return true, writeHelperFailure(stdout, ErrorTargetMismatch)
	}

	backend := deps.newBackend(cfg.YKCS11Path)
	if backend == nil {
		return true, writeHelperFailure(stdout, ErrorProbe)
	}
	defer backend.Close()

	result, class := execute(ctx, request, cfg, backend)
	if class != "" {
		clear(result.PublicKey[:])
		return true, writeHelperFailure(stdout, class)
	}
	defer clear(result.PublicKey[:])
	response, err := marshalSuccess(request.Operation, result)
	if err != nil {
		return true, writeHelperFailure(stdout, ErrorHelper)
	}
	defer clear(response)
	if writeFrame(stdout, response, maxResponseFrame) != nil {
		return true, helperFailureCode
	}
	return true, 0
}

func execute(ctx context.Context, request request, cfg config.Config, backend publicBackend) (response, ErrorClass) {
	if err := ctx.Err(); err != nil {
		return response{}, contextClass(err)
	}
	switch request.Operation {
	case OperationReadPublic:
		publicKey, err := backend.ReadPublic(ctx, request.Serial, request.Slot)
		if err != nil {
			clear(publicKey[:])
			return response{}, hardwareClass(err)
		}
		return response{PublicKey: publicKey}, ""
	case OperationProbe:
		configured, ok := configuredPublicKey(cfg)
		if !ok {
			return response{}, ErrorConfiguration
		}
		defer clear(configured[:])
		if subtle.ConstantTimeCompare(request.PublicKey[:], configured[:]) != 1 {
			return response{}, ErrorTargetMismatch
		}
		result, err := backend.Probe(ctx, agehardware.Target{
			Serial:    request.Serial,
			Slot:      request.Slot,
			PublicKey: request.PublicKey,
		})
		if contextErr := ctx.Err(); contextErr != nil {
			return response{}, contextClass(contextErr)
		}
		switch result.State {
		case agehardware.Connected, agehardware.NotDetected:
			if err == nil {
				return response{State: result.State}, ""
			}
		case agehardware.Mismatch:
			return response{}, ErrorTargetMismatch
		case agehardware.Unavailable:
			return response{}, ErrorProbe
		}
		return response{}, hardwareClass(err)
	default:
		return response{}, ErrorInvalidRequest
	}
}

func configuredPublicKey(cfg config.Config) ([32]byte, bool) {
	var publicKey [32]byte
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
	if _, err := ageprofile.NewRecipient(ageprofile.PublicKey(publicKey), nil); err != nil {
		clear(publicKey[:])
		return [32]byte{}, false
	}
	return publicKey, true
}

func writeHelperFailure(stdout io.Writer, class ErrorClass) int {
	encoded := marshalFailure(class)
	defer clear(encoded)
	if err := writeFrame(stdout, encoded, maxResponseFrame); err != nil {
		return helperFailureCode
	}
	return helperFailureCode
}
