package system

import (
	"os"
	"path/filepath"
	"strings"
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

func TestInspectSSHConfigWithTargets(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	targets := SSHConfigTargets{
		PublicAgentSocket:  filepath.Join(home, ".ssh", "yubitouch", "agent.sock"),
		PIVAgentSocket:     filepath.Join(home, ".ssh", "yubitouch", "piv-agent.sock"),
		BackendAgentSocket: filepath.Join(home, ".ssh", "yubitouch", "backend.sock"),
		PublicIdentityFile: filepath.Join(home, ".ssh", "yubikey-piv.pub"),
	}
	contents := "Host public\n" +
		"  IdentityAgent=\"%d/.ssh/yubitouch/agent.sock\"\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub\n" +
		"  IdentitiesOnly YES\n" +
		"Host internal-piv\n" +
		"  IdentityAgent ~/.ssh/yubitouch/piv-agent.sock\n" +
		"Host internal-backend\n" +
		"  IdentityAgent ~/.ssh/yubitouch/backend.sock\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Exists || !report.UsesPublicAgent || !report.UsesPIVAgent || !report.UsesBackend ||
		!report.UsesPublicIdentityFile || !report.UsesIdentitiesOnly || !report.UsesSafePublicIdentityConfig {
		t.Fatalf("report = %+v", report)
	}
}

func TestInspectSSHConfigWithTargetsRequiresExactSafeValues(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	targets := SSHConfigTargets{
		PublicAgentSocket:  filepath.Join(home, ".ssh", "yubitouch", "agent.sock"),
		PIVAgentSocket:     filepath.Join(home, ".ssh", "yubitouch", "piv-agent.sock"),
		BackendAgentSocket: filepath.Join(home, ".ssh", "yubitouch", "backend.sock"),
		PublicIdentityFile: filepath.Join(home, ".ssh", "yubikey-piv.pub"),
	}
	contents := "Host wrong\n" +
		"  IdentityAgent ~/.ssh/yubitouch/agent.sock.other\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub.old\n" +
		"  IdentitiesOnly no\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Exists || report.UsesPublicAgent || report.UsesPIVAgent || report.UsesBackend ||
		report.UsesPublicIdentityFile || report.UsesIdentitiesOnly {
		t.Fatalf("report = %+v", report)
	}
}

func TestInspectSSHConfigWithTargetsIgnoresEmptyTargets(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("Host dot\n  IdentityAgent .\n  IdentityFile .\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, SSHConfigTargets{})
	if err != nil {
		t.Fatal(err)
	}
	if report.UsesPublicAgent || report.UsesPIVAgent || report.UsesBackend || report.UsesPublicIdentityFile {
		t.Fatalf("report = %+v", report)
	}
}

func TestInspectSSHConfigWithTargetsMissingFile(t *testing.T) {
	report, err := InspectSSHConfigWithTargets(
		filepath.Join(t.TempDir(), "missing"),
		t.TempDir(),
		SSHConfigTargets{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if report != (SSHConfigReport{}) {
		t.Fatalf("report = %+v", report)
	}
}

func TestInspectSSHConfigSafeIdentityConfigMustBeInOneBlock(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	targets := testSSHConfigTargets(home)
	contents := "Host agent-only\n" +
		"  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
		"Host identity-only\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub\n" +
		"  IdentitiesOnly yes\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !report.UsesPublicAgent || !report.UsesPublicIdentityFile || !report.UsesIdentitiesOnly {
		t.Fatalf("expected diagnostic fields to record all directives: %+v", report)
	}
	if report.UsesSafePublicIdentityConfig {
		t.Fatalf("split Host blocks must not be reported safe: %+v", report)
	}
}

func TestInspectSSHConfigSafeIdentityConfigUsesFirstSingleValue(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	targets := testSSHConfigTargets(home)
	contents := "Host wrong-first-value\n" +
		"  IdentityAgent ~/.ssh/another-agent.sock\n" +
		"  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
		"  IdentitiesOnly yes\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !report.UsesPublicAgent || !report.UsesIdentitiesOnly {
		t.Fatalf("expected later diagnostic matches: %+v", report)
	}
	if report.UsesSafePublicIdentityConfig {
		t.Fatalf("later IdentityAgent must not override its earlier value: %+v", report)
	}

	contents = "Host wrong-first-value\n" +
		"  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
		"  IdentitiesOnly no\n" +
		"  IdentitiesOnly yes\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = InspectSSHConfigWithTargets(path, home, targets)
	if err != nil {
		t.Fatal(err)
	}
	if report.UsesSafePublicIdentityConfig {
		t.Fatalf("later IdentitiesOnly must not override its earlier value: %+v", report)
	}
}

func TestInspectSSHConfigSafeIdentityConfigHonorsEarlierGlobalValues(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	contents := "IdentityAgent ~/.ssh/another-agent.sock\n" +
		"IdentitiesOnly no\n" +
		"Host wrong-global-defaults\n" +
		"  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
		"  IdentitiesOnly yes\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, testSSHConfigTargets(home))
	if err != nil {
		t.Fatal(err)
	}
	if report.UsesSafePublicIdentityConfig {
		t.Fatalf("global first values must take precedence over Host values: %+v", report)
	}
}

func TestInspectSSHConfigSafeIdentityConfigHonorsEarlierHostStar(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	contents := "Host *\n" +
		"  IdentityAgent ~/.ssh/onepassword-agent.sock\n" +
		"  IdentitiesOnly no\n" +
		"Host rn\n" +
		"  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub\n" +
		"  IdentitiesOnly yes\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, testSSHConfigTargets(home))
	if err != nil {
		t.Fatal(err)
	}
	if !report.UsesPublicAgent || !report.UsesPublicIdentityFile || !report.UsesIdentitiesOnly {
		t.Fatalf("expected diagnostic fields to record the later Host: %+v", report)
	}
	if report.UsesSafePublicIdentityConfig {
		t.Fatalf("earlier Host * values must win for rn: %+v", report)
	}
}

func TestInspectSSHConfigSafeIdentityConfigMatchesEarlierHostPatterns(t *testing.T) {
	tests := []struct {
		name       string
		patterns   string
		expectSafe bool
	}{
		{name: "star suffix", patterns: "r*"},
		{name: "question mark", patterns: "r?"},
		{name: "character class", patterns: "r[nx]"},
		{name: "negated literal", patterns: "r* !rn", expectSafe: true},
		{name: "disjoint literal", patterns: "other", expectSafe: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "config")
			contents := "Host " + test.patterns + "\n" +
				"  IdentityAgent ~/.ssh/onepassword-agent.sock\n" +
				"  IdentitiesOnly no\n" +
				"Host rn\n" +
				"  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
				"  IdentityFile ~/.ssh/yubikey-piv.pub\n" +
				"  IdentitiesOnly yes\n"
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}

			report, err := InspectSSHConfigWithTargets(path, home, testSSHConfigTargets(home))
			if err != nil {
				t.Fatal(err)
			}
			if report.UsesSafePublicIdentityConfig != test.expectSafe {
				t.Fatalf("safe = %t, want %t; report = %+v", report.UsesSafePublicIdentityConfig, test.expectSafe, report)
			}
		})
	}
}

func TestInspectSSHConfigInspectsIncludedInternalSockets(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, "conf.d")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("Include conf.d/*.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(configDir, "backend.conf"),
		[]byte("Host backend\n  IdentityAgent ~/.ssh/yubitouch/backend.sock\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(configDir, "piv.conf"),
		[]byte("Host piv\n  IdentityAgent ~/.ssh/yubitouch/piv-agent.sock\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, testSSHConfigTargets(home))
	if err != nil {
		t.Fatal(err)
	}
	if !report.UsesPIVAgent || !report.UsesBackend {
		t.Fatalf("included internal sockets were not detected: %+v", report)
	}
}

func TestInspectSSHConfigIncludeCanCompleteCurrentHostBlock(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	if err := os.WriteFile(
		path,
		[]byte("Host safe\n  IdentityAgent ~/.ssh/yubitouch/agent.sock\n  Include identity.conf\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(home, "identity.conf"),
		[]byte("IdentityFile ~/.ssh/yubikey-piv.pub\nIdentitiesOnly yes\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, testSSHConfigTargets(home))
	if err != nil {
		t.Fatal(err)
	}
	if !report.UsesSafePublicIdentityConfig {
		t.Fatalf("included directives should remain in the current Host block: %+v", report)
	}
}

func TestInspectSSHConfigRejectsIncludeCycle(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	included := filepath.Join(home, "included.conf")
	contents := "Host safe\n" +
		"  IdentityAgent ~/.ssh/yubitouch/agent.sock\n" +
		"  IdentityFile ~/.ssh/yubikey-piv.pub\n" +
		"  IdentitiesOnly yes\n" +
		"Host cycle\n" +
		"  Include included.conf\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(included, []byte("Include config\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectSSHConfigWithTargets(path, home, testSSHConfigTargets(home))
	if err == nil || !strings.Contains(err.Error(), "include cycle") {
		t.Fatalf("error = %v", err)
	}
	if report.UsesSafePublicIdentityConfig {
		t.Fatalf("incomplete inspection must not report a safe config: %+v", report)
	}
}

func testSSHConfigTargets(home string) SSHConfigTargets {
	return SSHConfigTargets{
		PublicAgentSocket:  filepath.Join(home, ".ssh", "yubitouch", "agent.sock"),
		PIVAgentSocket:     filepath.Join(home, ".ssh", "yubitouch", "piv-agent.sock"),
		BackendAgentSocket: filepath.Join(home, ".ssh", "yubitouch", "backend.sock"),
		PublicIdentityFile: filepath.Join(home, ".ssh", "yubikey-piv.pub"),
	}
}
