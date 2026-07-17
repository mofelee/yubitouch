package pin

import (
	"context"
	"errors"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/mofelee/yubitouch/internal/buildinfo"
	"github.com/mofelee/yubitouch/internal/config"
)

var (
	ErrInvalidSecretReference        = errors.New("1Password secret reference syntax is invalid")
	ErrDesktopIntegrationUnavailable = errors.New("1Password Desktop App Integration is unavailable")
)

type onePasswordResolver struct {
	integrationVersion string
}

func (r onePasswordResolver) Resolve(ctx context.Context, cfg config.Config) ([]byte, error) {
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithDesktopAppIntegration(cfg.OnePasswordAccount),
		onepassword.WithIntegrationInfo("YubiTouch", r.integrationVersion),
	)
	if err != nil {
		return nil, err
	}
	secret, err := client.Secrets().Resolve(ctx, cfg.OnePasswordRef)
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, errors.New("1Password returned an empty secret")
	}
	// The SDK returns an immutable Go string. The AskPass process exits after
	// this copy is consumed so the secret is not retained by the daemon.
	return []byte(secret), nil
}

func CheckOnePassword(ctx context.Context, cfg config.Config) error {
	return checkOnePassword(
		ctx,
		cfg,
		onepassword.Secrets.ValidateSecretReference,
		connectDesktopApp,
	)
}

type referenceValidator func(context.Context, string) error

type desktopConnector func(context.Context, string) error

func checkOnePassword(ctx context.Context, cfg config.Config, validate referenceValidator, connect desktopConnector) error {
	if err := validate(ctx, cfg.OnePasswordRef); err != nil {
		return ErrInvalidSecretReference
	}
	if err := connect(ctx, cfg.OnePasswordAccount); err != nil {
		return ErrDesktopIntegrationUnavailable
	}
	return nil
}

func connectDesktopApp(ctx context.Context, account string) error {
	_, err := onepassword.NewClient(
		ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("YubiTouch", buildinfo.Version),
	)
	return err
}
