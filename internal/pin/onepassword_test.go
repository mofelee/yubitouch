package pin

import (
	"context"
	"errors"
	"testing"

	"github.com/mofelee/yubitouch/internal/config"
)

func TestCheckOnePasswordValidatesReferenceThenConnectsWithoutResolving(t *testing.T) {
	cfg := config.Config{
		OnePasswordAccount: "Example Account",
		OnePasswordRef:     "op://Personal/YubiKey PIV/pin",
	}
	validated := false
	connected := false
	err := checkOnePassword(
		context.Background(),
		cfg,
		func(_ context.Context, reference string) error {
			validated = true
			if reference != cfg.OnePasswordRef {
				t.Fatalf("reference = %q", reference)
			}
			return nil
		},
		func(_ context.Context, account string) error {
			connected = true
			if account != cfg.OnePasswordAccount {
				t.Fatalf("account = %q", account)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !validated || !connected {
		t.Fatalf("validated=%v connected=%v", validated, connected)
	}
}

func TestCheckOnePasswordReturnsOnlySafeClassifiedErrors(t *testing.T) {
	sensitive := errors.New("op://Personal/YubiKey/PIN contained 123456")
	cfg := config.Config{OnePasswordAccount: "Secret Account", OnePasswordRef: "op://vault/item/field"}

	err := checkOnePassword(context.Background(), cfg, func(context.Context, string) error {
		return sensitive
	}, func(context.Context, string) error {
		t.Fatal("desktop connector ran after invalid reference")
		return nil
	})
	if !errors.Is(err, ErrInvalidSecretReference) || errors.Is(err, sensitive) {
		t.Fatalf("reference error = %v", err)
	}

	err = checkOnePassword(context.Background(), cfg, func(context.Context, string) error {
		return nil
	}, func(context.Context, string) error {
		return sensitive
	})
	if !errors.Is(err, ErrDesktopIntegrationUnavailable) || errors.Is(err, sensitive) {
		t.Fatalf("desktop error = %v", err)
	}
}
