package agentroute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mofelee/yubitouch/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrFallbackUnavailable    = errors.New("1Password fallback agent is unavailable")
	ErrFallbackKeyUnavailable = errors.New("1Password fallback agent does not contain the configured target key")
)

type FallbackReport struct {
	Reachable      bool
	TargetKeyFound bool
	OtherKeys      int
}

func InspectFallback(ctx context.Context, cfg config.Config) (FallbackReport, error) {
	if err := validateSocket(cfg.FallbackAgentSocket, cfg.PIVSocketPath, cfg.BackendSocketPath); err != nil {
		return FallbackReport{}, fmt.Errorf("%w: %v", ErrFallbackUnavailable, err)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", cfg.FallbackAgentSocket)
	if err != nil {
		return FallbackReport{}, fmt.Errorf("%w: cannot connect", ErrFallbackUnavailable)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stop()
		_ = conn.Close()
	}()

	report := FallbackReport{Reachable: true}
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return report, fmt.Errorf("%w: identity query failed", ErrFallbackUnavailable)
	}
	for _, key := range keys {
		parsed, parseErr := ssh.ParsePublicKey(key.Blob)
		if parseErr == nil && samePublicKey(parsed, cfg.PublicKey) {
			report.TargetKeyFound = true
		} else {
			report.OtherKeys++
		}
	}
	if !report.TargetKeyFound {
		return report, ErrFallbackKeyUnavailable
	}
	return report, nil
}

func validateSocket(path string, managedPaths ...string) error {
	if path == "" {
		return errors.New("socket path is empty")
	}
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("socket parent: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errors.New("socket does not exist")
		}
		return errors.New("cannot inspect socket")
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return errors.New("path is not a Unix socket")
	}
	if !ownedByCurrentUser(info) {
		return errors.New("socket is not owned by the current user")
	}
	for _, managedPath := range managedPaths {
		managed, statErr := os.Stat(managedPath)
		if statErr == nil && os.SameFile(info, managed) {
			return errors.New("socket resolves to a YubiTouch managed socket")
		}
	}
	return nil
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("cannot inspect directory")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path is not a directory")
	}
	if !ownedByCurrentUser(info) {
		return errors.New("directory is not owned by the current user")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory is writable by group or others")
	}
	return nil
}

func ownedByCurrentUser(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func samePublicKey(left ssh.PublicKey, right ssh.PublicKey) bool {
	return left != nil && right != nil && bytes.Equal(left.Marshal(), right.Marshal())
}
