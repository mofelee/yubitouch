package pin

import (
	"context"
	"errors"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/mofelee/yubitouch/internal/config"
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
