package system

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mofelee/yubitouch/internal/config"
)

type Dependencies struct {
	SSHAgent  string `json:"ssh_agent"`
	SSHAdd    string `json:"ssh_add"`
	SSHKeygen string `json:"ssh_keygen"`
	YKCS11    string `json:"ykcs11"`
}

func Resolve(cfg config.Config) (Dependencies, error) {
	provider, err := ResolveYKCS11(cfg.YKCS11Path)
	if err != nil {
		return Dependencies{}, err
	}
	deps := Dependencies{
		SSHAgent:  filepath.Join(cfg.OpenSSHPrefix, "bin", "ssh-agent"),
		SSHAdd:    filepath.Join(cfg.OpenSSHPrefix, "bin", "ssh-add"),
		SSHKeygen: filepath.Join(cfg.OpenSSHPrefix, "bin", "ssh-keygen"),
		YKCS11:    provider,
	}
	checks := []struct {
		name string
		path string
	}{
		{"ssh-agent", deps.SSHAgent},
		{"ssh-add", deps.SSHAdd},
		{"ssh-keygen", deps.SSHKeygen},
		{"libykcs11", deps.YKCS11},
	}
	for _, check := range checks {
		info, err := os.Stat(check.path)
		if err != nil {
			return Dependencies{}, fmt.Errorf("%s not found at %s: %w", check.name, check.path, err)
		}
		if info.IsDir() {
			return Dependencies{}, fmt.Errorf("%s path is a directory: %s", check.name, check.path)
		}
	}
	return deps, nil
}

func ResolveYKCS11(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("libykcs11 not found at %s: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("libykcs11 not found at %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("libykcs11 path is a directory: %s", path)
	}
	return resolved, nil
}
