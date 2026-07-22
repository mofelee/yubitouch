package command

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
)

const ageCommandUsage = "usage: yubitouch age <recipient|identity>"

// AgeHardwareReader is the public-key-only process boundary for age hardware.
// ReadPublic must not log in to the token or request PIN/touch.
type AgeHardwareReader interface {
	ReadPublic(context.Context, string, string) ([32]byte, error)
}

func runAge(args []string, stdout io.Writer, stderr io.Writer, env Environment) int {
	if len(args) != 1 || (args[0] != "recipient" && args[0] != "identity") {
		fmt.Fprintln(stderr, ageCommandUsage)
		return ExitConfigError
	}

	path := config.PathFromEnvironment(env.Home, env.Getenv)
	cfg, err := config.Load(path, env.Home)
	if err != nil {
		fmt.Fprintln(stderr, "age configuration is unavailable or invalid; run yubitouch configure")
		return ExitConfigError
	}
	if cfg.Age == nil {
		fmt.Fprintln(stderr, "age is not configured; run yubitouch configure")
		return ExitConfigError
	}

	hardwarePublicKey, cacheRequired, code := resolveAgePublicKey(stderr, cfg, env)
	if code != ExitOK {
		return code
	}
	identity, identityErr := ageprofile.EncodeIdentity(hardwarePublicKey)
	if identityErr != nil {
		if cacheRequired {
			fmt.Fprintln(stderr, "the YubiKey returned an invalid age public key")
			return ExitRuntimeError
		}
		fmt.Fprintln(stderr, "age public key configuration is invalid")
		return ExitConfigError
	}
	if cacheRequired {
		target := config.AgeTarget{
			Serial:    cfg.Age.Serial,
			Slot:      cfg.Age.Slot,
			Algorithm: cfg.Age.Algorithm,
		}
		latest, err := config.CacheAgePublicKey(path, env.Home, target, hardwarePublicKey)
		if err != nil {
			if errors.Is(err, config.ErrAgeConfigurationChanged) {
				fmt.Fprintln(stderr, "age configuration changed while reading the YubiKey; retry the command")
			} else {
				fmt.Fprintln(stderr, "cannot persist the age public key cache")
			}
			return ExitRuntimeError
		}
		cfg = latest
	}

	var output string
	switch args[0] {
	case "recipient":
		var recoveryPublicKey *ageprofile.PublicKey
		if cfg.Age.Recovery != nil {
			parsed, parseErr := ageprofile.ParseNativeRecipient(cfg.Age.Recovery.Recipient)
			if parseErr != nil {
				fmt.Fprintln(stderr, "age recovery recipient configuration is invalid")
				return ExitConfigError
			}
			recoveryPublicKey = &parsed
		}
		recipient, recipientErr := ageprofile.NewRecipient(hardwarePublicKey, recoveryPublicKey)
		if recipientErr != nil {
			fmt.Fprintln(stderr, "age public key configuration is invalid")
			return ExitConfigError
		}
		output = recipient.String()
	case "identity":
		output = identity
	}

	fmt.Fprintln(stdout, output)
	return ExitOK
}

func resolveAgePublicKey(stderr io.Writer, cfg config.Config, env Environment) (ageprofile.PublicKey, bool, int) {
	if cfg.Age.PublicKey != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cfg.Age.PublicKey)
		if err != nil || len(decoded) != len(ageprofile.PublicKey{}) {
			fmt.Fprintln(stderr, "cached age public key configuration is invalid")
			return ageprofile.PublicKey{}, false, ExitConfigError
		}
		var publicKey ageprofile.PublicKey
		copy(publicKey[:], decoded)
		return publicKey, false, ExitOK
	}

	if env.NewAgeHardwareReader == nil {
		fmt.Fprintln(stderr, "age hardware public-key reader is unavailable")
		return ageprofile.PublicKey{}, false, ExitRuntimeError
	}
	reader := env.NewAgeHardwareReader(config.PathFromEnvironment(env.Home, env.Getenv))
	if reader == nil {
		fmt.Fprintln(stderr, "age hardware public-key reader is unavailable")
		return ageprofile.PublicKey{}, false, ExitRuntimeError
	}
	if closer, ok := reader.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	signalCtx, stopSignals := env.AgeSignalContext(context.Background())
	defer stopSignals()
	ctx, cancelTimeout := context.WithTimeout(signalCtx, 5*time.Second)
	defer cancelTimeout()
	publicKey, err := reader.ReadPublic(ctx, cfg.Age.Serial, cfg.Age.Slot)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read the configured age public key from the YubiKey")
		return ageprofile.PublicKey{}, false, ExitRuntimeError
	}
	return ageprofile.PublicKey(publicKey), true, ExitOK
}
