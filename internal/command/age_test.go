package command

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mofelee/yubitouch/internal/ageprobe"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
)

type fakeAgeHardwareReader struct {
	publicKey ageprofile.PublicKey
	err       error
	before    func()
	calls     int
	serial    string
	slot      string
	closed    bool
}

func (f *fakeAgeHardwareReader) ReadPublic(ctx context.Context, serial string, slot string) ([32]byte, error) {
	f.calls++
	f.serial = serial
	f.slot = slot
	if f.before != nil {
		f.before()
	}
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	return [32]byte(f.publicKey), f.err
}

func (f *fakeAgeHardwareReader) Close() error {
	f.closed = true
	return nil
}

func TestAgeCommandsUseCachedPublicKeyWithoutHardware(t *testing.T) {
	home, _, cfg, hardwarePublicKey, recoveryPublicKey := writeAgeCommandConfig(t, true, true)
	factoryCalls := 0
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader {
		factoryCalls++
		return &fakeAgeHardwareReader{err: errors.New("must not be called")}
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "recipient"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("recipient exit %d: %s", code, stderr.String())
	}
	assertSingleOutputLine(t, stdout.String())
	if stderr.Len() != 0 {
		t.Fatalf("recipient stderr = %q", stderr.String())
	}
	if factoryCalls != 0 {
		t.Fatalf("cached recipient created %d hardware reader(s)", factoryCalls)
	}
	recipient, err := ageprofile.ParseRecipient(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	if got := recipient.Hardware().PublicKey; got != hardwarePublicKey {
		t.Fatal("recipient hardware public key does not match the cache")
	}
	recovery, ok := recipient.Recovery()
	if !ok || recovery.PublicKey != recoveryPublicKey {
		t.Fatal("recipient is not bound to the configured public recovery recipient")
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"age", "identity"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("identity exit %d: %s", code, stderr.String())
	}
	assertSingleOutputLine(t, stdout.String())
	wantIdentity, err := ageprofile.EncodeIdentity(hardwarePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != wantIdentity {
		t.Fatalf("identity = %q, want %q", got, wantIdentity)
	}
	if factoryCalls != 0 {
		t.Fatalf("cached identity created %d hardware reader(s)", factoryCalls)
	}
	for _, sensitive := range []string{cfg.Age.Serial, cfg.Age.Recovery.IdentityRef, cfg.OnePasswordAccount} {
		if strings.Contains(stdout.String(), sensitive) || strings.Contains(stderr.String(), sensitive) {
			t.Fatalf("age output exposed private configuration value %q", sensitive)
		}
	}
}

func TestProductionAgeHardwareReaderUsesSubprocessBoundary(t *testing.T) {
	reader := newAgeHardwareReader(filepath.Join(t.TempDir(), "config.json"))
	if _, ok := reader.(*ageprobe.Runner); !ok {
		t.Fatalf("production reader type = %T, want *ageprobe.Runner", reader)
	}
}

func TestAgeCommandReadsAndCachesHardwarePublicKeyOnce(t *testing.T) {
	home, path, cfg, hardwarePublicKey, _ := writeAgeCommandConfig(t, false, false)
	reader := &fakeAgeHardwareReader{publicKey: hardwarePublicKey}
	factoryCalls := 0
	readerConfigPath := ""
	env := ageCommandEnvironment(home, func(gotConfigPath string) AgeHardwareReader {
		factoryCalls++
		readerConfigPath = gotConfigPath
		return reader
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "recipient"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("recipient exit %d: %s", code, stderr.String())
	}
	assertSingleOutputLine(t, stdout.String())
	if stderr.Len() != 0 {
		t.Fatalf("recipient stderr = %q", stderr.String())
	}
	if factoryCalls != 1 || reader.calls != 1 || !reader.closed {
		t.Fatalf("hardware reader lifecycle: factories=%d calls=%d closed=%v", factoryCalls, reader.calls, reader.closed)
	}
	if readerConfigPath != path || reader.serial != cfg.Age.Serial || reader.slot != cfg.Age.Slot {
		t.Fatal("hardware reader did not receive the configured path and target")
	}

	loaded, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	wantCache := base64.RawURLEncoding.EncodeToString(hardwarePublicKey[:])
	if loaded.Age == nil || loaded.Age.PublicKey != wantCache {
		t.Fatalf("cached public key = %+v, want %q", loaded.Age, wantCache)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cached config mode = %04o, want 0600", info.Mode().Perm())
	}

	stdout.Reset()
	stderr.Reset()
	env.NewAgeHardwareReader = func(string) AgeHardwareReader {
		t.Fatal("identity touched hardware after the public key was cached")
		return nil
	}
	if code := Run([]string{"age", "identity"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("identity exit %d: %s", code, stderr.String())
	}
	assertSingleOutputLine(t, stdout.String())
}

func TestAgeCommandCachePreservesConcurrentConfigure(t *testing.T) {
	home, path, _, hardwarePublicKey, _ := writeAgeCommandConfig(t, false, false)
	readStarted := make(chan struct{})
	resumeRead := make(chan struct{})
	reader := &fakeAgeHardwareReader{
		publicKey: hardwarePublicKey,
		before: func() {
			close(readStarted)
			<-resumeRead
		},
	}
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader { return reader })
	type result struct {
		code   int
		stdout string
		stderr string
	}
	resultCh := make(chan result, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code := Run([]string{"age", "recipient"}, &stdout, &stderr, env)
		resultCh <- result{code: code, stdout: stdout.String(), stderr: stderr.String()}
	}()
	<-readStarted

	recoveryIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		close(resumeRead)
		t.Fatal(err)
	}
	values := map[string]string{
		"YUBITOUCH_LOG_LEVEL":                 "debug",
		"YUBITOUCH_1PASSWORD_ACCOUNT":         "Concurrent Account",
		"YUBITOUCH_AGE_RECOVERY_PROVIDER":     "1password",
		"YUBITOUCH_AGE_RECOVERY_IDENTITY_REF": "op://Concurrent Vault/Recovery/private-key",
		"YUBITOUCH_AGE_RECOVERY_RECIPIENT":    recoveryIdentity.Recipient().String(),
	}
	configureEnv := Environment{
		Home:   home,
		Getenv: func(name string) string { return values[name] },
	}
	var configureStdout, configureStderr bytes.Buffer
	configureCode := Run([]string{"configure"}, &configureStdout, &configureStderr, configureEnv)
	close(resumeRead)
	if configureCode != ExitOK {
		t.Fatalf("concurrent configure exit %d: %s", configureCode, configureStderr.String())
	}

	var got result
	select {
	case got = <-resultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("age command did not finish after the hardware read resumed")
	}
	if got.code != ExitOK || got.stderr != "" {
		t.Fatalf("age command exit=%d stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
	}
	recipient, err := ageprofile.ParseRecipient(strings.TrimSpace(got.stdout))
	if err != nil {
		t.Fatal(err)
	}
	wantRecovery, err := ageprofile.ParseNativeRecipient(recoveryIdentity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	recovery, ok := recipient.Recovery()
	if !ok || recovery.PublicKey != wantRecovery {
		t.Fatal("age recipient did not use the concurrently configured recovery recipient")
	}

	loaded, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	wantCache := base64.RawURLEncoding.EncodeToString(hardwarePublicKey[:])
	if loaded.LogLevel != "debug" || loaded.OnePasswordAccount != "Concurrent Account" || loaded.Age.PublicKey != wantCache {
		t.Fatalf("concurrent configuration was not preserved: log=%q account=%q cache=%q", loaded.LogLevel, loaded.OnePasswordAccount, loaded.Age.PublicKey)
	}
	if loaded.Age.Recovery == nil || loaded.Age.Recovery.IdentityRef != values["YUBITOUCH_AGE_RECOVERY_IDENTITY_REF"] {
		t.Fatal("concurrently configured recovery settings were not preserved")
	}
}

func TestAgeCommandRejectsConcurrentTargetChangeWithoutCachingOrOutput(t *testing.T) {
	home, path, _, hardwarePublicKey, _ := writeAgeCommandConfig(t, false, false)
	readStarted := make(chan struct{})
	resumeRead := make(chan struct{})
	reader := &fakeAgeHardwareReader{
		publicKey: hardwarePublicKey,
		before: func() {
			close(readStarted)
			<-resumeRead
		},
	}
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader { return reader })
	type result struct {
		code   int
		stdout string
		stderr string
	}
	resultCh := make(chan result, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code := Run([]string{"age", "identity"}, &stdout, &stderr, env)
		resultCh <- result{code: code, stdout: stdout.String(), stderr: stderr.String()}
	}()
	<-readStarted

	values := map[string]string{"YUBITOUCH_AGE_SERIAL": "87654321"}
	configureEnv := Environment{
		Home:   home,
		Getenv: func(name string) string { return values[name] },
	}
	var configureStdout, configureStderr bytes.Buffer
	configureCode := Run([]string{"configure"}, &configureStdout, &configureStderr, configureEnv)
	close(resumeRead)
	if configureCode != ExitOK {
		t.Fatalf("concurrent configure exit %d: %s", configureCode, configureStderr.String())
	}

	var got result
	select {
	case got = <-resultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("age command did not finish after the hardware read resumed")
	}
	if got.code != ExitRuntimeError || got.stdout != "" || !strings.Contains(got.stderr, "configuration changed") {
		t.Fatalf("age command exit=%d stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
	}
	loaded, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Age.Serial != "87654321" || loaded.Age.PublicKey != "" {
		t.Fatalf("changed target/cache = %q/%q", loaded.Age.Serial, loaded.Age.PublicKey)
	}
}

func TestAgeCommandHardwareFailureIsRedactedAndDoesNotCache(t *testing.T) {
	home, path, _, _, _ := writeAgeCommandConfig(t, false, false)
	const sensitive = "serial=12345678 provider-secret"
	reader := &fakeAgeHardwareReader{err: errors.New(sensitive)}
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader { return reader })

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "recipient"}, &stdout, &stderr, env); code != ExitRuntimeError {
		t.Fatalf("recipient exit %d, want %d", code, ExitRuntimeError)
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), sensitive) {
		t.Fatalf("hardware failure output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	loaded, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Age.PublicKey != "" {
		t.Fatalf("failed hardware read cached public key %q", loaded.Age.PublicKey)
	}
}

func TestAgeCommandSignalCancellationDoesNotOutputOrCache(t *testing.T) {
	home, path, _, hardwarePublicKey, _ := writeAgeCommandConfig(t, false, false)
	reader := &fakeAgeHardwareReader{publicKey: hardwarePublicKey}
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader { return reader })
	var signalCancel context.CancelFunc
	env.AgeSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		signalCancel = cancel
		return ctx, func() {}
	}
	reader.before = func() { signalCancel() }

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "recipient"}, &stdout, &stderr, env); code != ExitRuntimeError {
		t.Fatalf("recipient exit %d, want %d", code, ExitRuntimeError)
	}
	if stdout.Len() != 0 || reader.calls != 1 || !reader.closed {
		t.Fatalf("stdout=%q calls=%d closed=%v", stdout.String(), reader.calls, reader.closed)
	}
	loaded, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Age.PublicKey != "" {
		t.Fatal("signal-canceled public read was cached")
	}
}

func TestAgeCommandRejectsInvalidHardwarePublicKeyWithoutCaching(t *testing.T) {
	home, path, _, _, _ := writeAgeCommandConfig(t, false, false)
	reader := &fakeAgeHardwareReader{}
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader { return reader })

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "identity"}, &stdout, &stderr, env); code != ExitRuntimeError {
		t.Fatalf("identity exit %d, want %d", code, ExitRuntimeError)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid age public key") {
		t.Fatalf("invalid public key output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	loaded, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Age.PublicKey != "" {
		t.Fatalf("invalid hardware public key was cached as %q", loaded.Age.PublicKey)
	}
}

func TestAgeCommandRejectsInvalidCachedPublicKeyWithoutHardware(t *testing.T) {
	home, path, cfg, _, _ := writeAgeCommandConfig(t, true, false)
	cfg.Age.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	factoryCalls := 0
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader {
		factoryCalls++
		return nil
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "recipient"}, &stdout, &stderr, env); code != ExitConfigError {
		t.Fatalf("recipient exit %d, want %d", code, ExitConfigError)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "configuration is unavailable or invalid") {
		t.Fatalf("invalid cache output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if factoryCalls != 0 {
		t.Fatalf("invalid cached key created %d hardware reader(s)", factoryCalls)
	}
}

func TestAgeCommandReportsCacheSaveFailureWithoutOutput(t *testing.T) {
	home, path, _, hardwarePublicKey, _ := writeAgeCommandConfig(t, false, false)
	reader := &fakeAgeHardwareReader{
		publicKey: hardwarePublicKey,
		before: func() {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	env := ageCommandEnvironment(home, func(string) AgeHardwareReader { return reader })

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "identity"}, &stdout, &stderr, env); code != ExitRuntimeError {
		t.Fatalf("identity exit %d, want %d", code, ExitRuntimeError)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "persist") {
		t.Fatalf("save failure output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAgeCommandRejectsInvalidArgumentsAndMissingConfiguration(t *testing.T) {
	env := ageCommandEnvironment(t.TempDir(), func(string) AgeHardwareReader {
		t.Fatal("invalid age command touched hardware")
		return nil
	})
	for _, args := range [][]string{
		{"age"},
		{"age", "unknown"},
		{"age", "recipient", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr, env); code != ExitConfigError {
			t.Fatalf("Run(%v) exit %d, want %d", args, code, ExitConfigError)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), ageCommandUsage) {
			t.Fatalf("Run(%v) stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"age", "recipient"}, &stdout, &stderr, env); code != ExitConfigError {
		t.Fatalf("missing config exit %d, want %d", code, ExitConfigError)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "configuration") {
		t.Fatalf("missing config output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	home := makeBaseCommandConfig(t)
	env.Home = home
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"age", "identity"}, &stdout, &stderr, env); code != ExitConfigError {
		t.Fatalf("missing age profile exit %d, want %d", code, ExitConfigError)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "age is not configured") {
		t.Fatalf("missing age output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestStatusReportsOnlySafeAgeConfigurationFields(t *testing.T) {
	home, _, cfg, _, _ := writeAgeCommandConfig(t, true, true)
	listener := listenStatusSocket(t, cfg.AgeSocketPath)
	defer listener.Close()
	env := ageCommandEnvironment(home, nil)
	env.ProbeYubiKeys = func(context.Context) (int, error) { return 0, nil }

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"status", "--json"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("status exit %d: %s", code, stderr.String())
	}
	var status Status
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.AgeConfigured || !status.AgeSocketReachable || !status.AgeRecoveryConfigured {
		t.Fatalf("age status = %+v", status)
	}
	for _, forbidden := range []string{cfg.Age.Serial, cfg.Age.PublicKey, cfg.Age.Recovery.IdentityRef, cfg.Age.Recovery.Recipient} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("status JSON exposed age configuration value %q", forbidden)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"status"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("text status exit %d: %s", code, stderr.String())
	}
	for _, line := range []string{"age: configured\n", "age socket: reachable\n", "age recovery: configured\n"} {
		if !strings.Contains(stdout.String(), line) {
			t.Fatalf("text status missing %q: %s", line, stdout.String())
		}
	}
}

func ageCommandEnvironment(home string, factory func(string) AgeHardwareReader) Environment {
	return Environment{
		Home:                 home,
		Getenv:               func(string) string { return "" },
		NewAgeHardwareReader: factory,
		AgeSignalContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			return context.WithCancel(parent)
		},
	}
}

func writeAgeCommandConfig(t *testing.T, cached bool, recovery bool) (string, string, config.Config, ageprofile.PublicKey, ageprofile.PublicKey) {
	t.Helper()
	home := makeBaseCommandConfig(t)
	path := config.DefaultPath(home)
	cfg, err := config.Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	hardwarePublicKey := generateCommandAgePublicKey(t)
	cfg.Age = &config.AgeConfig{
		Serial:    "12345678",
		Slot:      "82",
		Algorithm: "x25519",
	}
	if cached {
		cfg.Age.PublicKey = base64.RawURLEncoding.EncodeToString(hardwarePublicKey[:])
	}
	var recoveryPublicKey ageprofile.PublicKey
	if recovery {
		recoveryIdentity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		recoveryPublicKey, err = ageprofile.ParseNativeRecipient(recoveryIdentity.Recipient().String())
		if err != nil {
			t.Fatal(err)
		}
		cfg.OnePasswordAccount = "Private Account"
		cfg.Age.Recovery = &config.AgeRecovery{
			Provider:    "1password",
			IdentityRef: "op://Private Vault/Recovery/private-key",
			Recipient:   recoveryIdentity.Recipient().String(),
		}
	}
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	return home, path, cfg, hardwarePublicKey, recoveryPublicKey
}

func makeBaseCommandConfig(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "yt-age-command-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults(home)
	cfg.PublicKeyPath = keyPath
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(config.DefaultPath(home), cfg); err != nil {
		t.Fatal(err)
	}
	return home
}

func generateCommandAgePublicKey(t *testing.T) ageprofile.PublicKey {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var publicKey ageprofile.PublicKey
	copy(publicKey[:], privateKey.PublicKey().Bytes())
	return publicKey
}

func assertSingleOutputLine(t *testing.T, output string) {
	t.Helper()
	if strings.Count(output, "\n") != 1 || !strings.HasSuffix(output, "\n") || strings.TrimSpace(output) == "" {
		t.Fatalf("success output is not exactly one line: %q", output)
	}
}
