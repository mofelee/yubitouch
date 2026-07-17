package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectSSHConfig(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	contents := "Host good\n  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
		"Host bad\n  IdentityAgent %d/.ssh/yubitouch/backend.sock\n" +
		"Match final exec \"%d/.local/bin/yubitouch ensure\"\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := InspectSSHConfig(
		path,
		home,
		filepath.Join(home, ".ssh", "yubitouch", "agent.sock"),
		filepath.Join(home, ".ssh", "yubitouch", "backend.sock"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Exists || !report.UsesPublicAgent || !report.UsesBackend || !report.HasMatchExec {
		t.Fatalf("report = %+v", report)
	}
}
