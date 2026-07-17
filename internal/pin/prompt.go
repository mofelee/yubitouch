package pin

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/native/macos"
	"golang.org/x/term"
)

type promptResolver struct{}

func (promptResolver) Resolve(ctx context.Context, _ config.Config) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	secret, err := macos.PromptPIN()
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, macos.ErrPromptUnavailable) {
		return nil, err
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no graphical session or controlling TTY is available")
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, "YubiKey PIV PIN (not saved): "); err != nil {
		return nil, err
	}
	secret, err = term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return nil, err
	}
	return secret, nil
}
