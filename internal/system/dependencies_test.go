package system

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mofelee/yubitouch/internal/config"
)

func TestResolveFollowsCurrentProviderOptLink(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "openssh")
	bin := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("tool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	providerDir := filepath.Join(dir, "provider")
	if err := os.MkdirAll(providerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(providerDir, "libykcs11.1.dylib")
	second := filepath.Join(providerDir, "libykcs11.2.dylib")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("provider"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stable := filepath.Join(providerDir, "libykcs11.dylib")
	if err := os.Symlink(filepath.Base(first), stable); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{OpenSSHPrefix: prefix, YKCS11Path: stable}

	deps, err := Resolve(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resolvedFirst, err := filepath.EvalSymlinks(first)
	if err != nil {
		t.Fatal(err)
	}
	if deps.YKCS11 != resolvedFirst {
		t.Fatalf("first provider = %q, want %q", deps.YKCS11, resolvedFirst)
	}
	if err := os.Remove(stable); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(second), stable); err != nil {
		t.Fatal(err)
	}
	deps, err = Resolve(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resolvedSecond, err := filepath.EvalSymlinks(second)
	if err != nil {
		t.Fatal(err)
	}
	if deps.YKCS11 != resolvedSecond {
		t.Fatalf("upgraded provider = %q, want %q", deps.YKCS11, resolvedSecond)
	}
}
