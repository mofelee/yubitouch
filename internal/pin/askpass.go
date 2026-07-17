package pin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mofelee/yubitouch/internal/buildinfo"
	"github.com/mofelee/yubitouch/internal/config"
)

const expectedPKCS11Prompt = "Enter passphrase for PKCS#11:"

type Resolver interface {
	Resolve(context.Context, config.Config) ([]byte, error)
}

type ResolverFactory func(config.Config) (Resolver, error)

func RunAskPass(ctx context.Context, prompt string, stdout io.Writer, stderr io.Writer, home string, getenv func(string) string) int {
	if strings.TrimSpace(prompt) != expectedPKCS11Prompt {
		fmt.Fprintln(stderr, "yubitouch askpass: refusing an unexpected prompt")
		return 4
	}
	path := config.PathFromEnvironment(home, getenv)
	guard := getenv("YUBITOUCH_ASKPASS_GUARD")
	if filepath.Dir(guard) != filepath.Dir(path) {
		fmt.Fprintln(stderr, "yubitouch askpass: invalid one-shot guard")
		return 4
	}
	if err := claimGuard(guard); err != nil {
		fmt.Fprintln(stderr, "yubitouch askpass: this request was already attempted")
		return 4
	}

	cfg, err := config.Load(path, home)
	if err != nil {
		fmt.Fprintln(stderr, "yubitouch askpass: configuration is unavailable")
		return 4
	}
	resolver, err := resolverFor(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "yubitouch askpass: PIN provider is unavailable")
		return 4
	}
	secret, err := resolver.Resolve(ctx, cfg)
	if err != nil || len(secret) == 0 {
		zero(secret)
		fmt.Fprintln(stderr, "yubitouch askpass: PIN provider failed or was canceled")
		return 4
	}
	defer zero(secret)
	if _, err := stdout.Write(secret); err != nil {
		fmt.Fprintln(stderr, "yubitouch askpass: cannot write the response")
		return 4
	}
	if _, err := io.WriteString(stdout, "\n"); err != nil {
		fmt.Fprintln(stderr, "yubitouch askpass: cannot finish the response")
		return 4
	}
	return 0
}

func resolverFor(cfg config.Config) (Resolver, error) {
	switch cfg.PINProvider {
	case config.PINProviderPrompt:
		return promptResolver{}, nil
	case config.PINProvider1Password:
		return onePasswordResolver{integrationVersion: buildinfo.Version}, nil
	default:
		return nil, fmt.Errorf("unsupported PIN provider %q", cfg.PINProvider)
	}
}

func claimGuard(path string) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return errors.New("missing askpass guard")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
