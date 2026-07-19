package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"

	"github.com/mofelee/yubitouch/internal/agentproxy"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type FallbackReport struct {
	Reachable      bool
	TargetKeyFound bool
	OtherKeys      int
}

func InspectFallback(ctx context.Context, cfg config.Config) (FallbackReport, error) {
	backend, err := connectFallback(ctx, cfg)
	if err != nil {
		return FallbackReport{}, err
	}
	defer backend.Close()
	report := FallbackReport{Reachable: true}
	keys, err := backend.rawAgent().List()
	if err != nil {
		return report, fmt.Errorf("%w: identity query failed", signing.ErrFallbackUnavailable)
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
		return report, signing.ErrFallbackKeyUnavailable
	}
	return report, nil
}

func connectFallback(ctx context.Context, cfg config.Config) (*fallbackClient, error) {
	if err := validateFallbackSocket(cfg); err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", cfg.FallbackAgentSocket)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot connect", signing.ErrFallbackUnavailable)
	}
	return &fallbackClient{client: newClient(ctx, conn), target: cfg.PublicKey}, nil
}

func validateFallbackSocket(cfg config.Config) error {
	info, err := os.Lstat(cfg.FallbackAgentSocket)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: socket does not exist", signing.ErrFallbackUnavailable)
		}
		return fmt.Errorf("%w: cannot inspect socket", signing.ErrFallbackUnavailable)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: path is not a Unix socket", signing.ErrFallbackUnavailable)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%w: socket is not owned by the current user", signing.ErrFallbackUnavailable)
	}
	for _, managedPath := range []string{cfg.SocketPath, cfg.BackendSocketPath} {
		managed, statErr := os.Stat(managedPath)
		if statErr == nil && os.SameFile(info, managed) {
			return fmt.Errorf("%w: socket resolves to a YubiTouch managed socket", signing.ErrFallbackUnavailable)
		}
	}
	return nil
}

type fallbackClient struct {
	client *client
	target ssh.PublicKey
}

func (c *fallbackClient) List() ([]*agent.Key, error) {
	keys, err := c.rawAgent().List()
	if err != nil {
		return nil, fmt.Errorf("%w: identity query failed", signing.ErrFallbackUnavailable)
	}
	for _, key := range keys {
		parsed, parseErr := ssh.ParsePublicKey(key.Blob)
		if parseErr == nil && samePublicKey(parsed, c.target) {
			return []*agent.Key{{
				Format:  key.Format,
				Blob:    append([]byte(nil), key.Blob...),
				Comment: key.Comment,
			}}, nil
		}
	}
	return nil, signing.ErrFallbackKeyUnavailable
}

func (c *fallbackClient) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

func (c *fallbackClient) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !samePublicKey(key, c.target) {
		return nil, agentproxy.ErrKeyNotAllowed
	}
	signature, err := c.rawAgent().SignWithFlags(key, data, flags)
	if err != nil {
		return nil, fmt.Errorf("%w: sign request failed", signing.ErrFallbackUnavailable)
	}
	return signature, nil
}

func (c *fallbackClient) Add(agent.AddedKey) error       { return agentproxy.ErrOperationDenied }
func (c *fallbackClient) Remove(ssh.PublicKey) error     { return agentproxy.ErrOperationDenied }
func (c *fallbackClient) RemoveAll() error               { return agentproxy.ErrOperationDenied }
func (c *fallbackClient) Lock([]byte) error              { return agentproxy.ErrOperationDenied }
func (c *fallbackClient) Unlock([]byte) error            { return agentproxy.ErrOperationDenied }
func (c *fallbackClient) Signers() ([]ssh.Signer, error) { return nil, agentproxy.ErrOperationDenied }

func (c *fallbackClient) Extension(extensionType string, contents []byte) ([]byte, error) {
	return c.rawAgent().Extension(extensionType, contents)
}

func (c *fallbackClient) Close() error         { return c.client.Close() }
func (c *fallbackClient) CloseAfterSign() bool { return true }
func (c *fallbackClient) rawAgent() agent.ExtendedAgent {
	return c.client.ExtendedAgent
}

func samePublicKey(left ssh.PublicKey, right ssh.PublicKey) bool {
	return left != nil && right != nil && bytes.Equal(left.Marshal(), right.Marshal())
}
