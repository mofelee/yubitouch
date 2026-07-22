package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mofelee/yubitouch/internal/ageipc"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
	"golang.org/x/crypto/ssh"
)

const pluginTestProcessEnvironment = "YUBITOUCH_AGE_PLUGIN_TEST_PROCESS"

func TestMain(m *testing.M) {
	if os.Getenv(pluginTestProcessEnvironment) == "1" {
		os.Exit(run())
	}
	os.Exit(m.Run())
}

func TestAgeCLIPluginOfflineEncryptAndIPCDecrypt(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("age-plugin-yubitouch is currently supported only on macOS")
	}
	agePath, err := exec.LookPath("age")
	if err != nil {
		t.Skip("age executable is not installed")
	}

	dir := shortTempDir(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var publicKey ageprofile.PublicKey
	copy(publicKey[:], privateKey.PublicKey().Bytes())
	recipient, err := ageprofile.NewRecipient(publicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ageprofile.EncodeIdentity(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	recipientPath := filepath.Join(dir, "recipient.txt")
	identityPath := filepath.Join(dir, "identity.txt")
	plaintextPath := filepath.Join(dir, "plaintext.txt")
	ciphertextPath := filepath.Join(dir, "ciphertext.age")
	outputPath := filepath.Join(dir, "output.txt")
	configPath := filepath.Join(dir, "config.json")
	plaintext := []byte("age CLI to YubiTouch plugin to daemon IPC round trip\n")
	if err := os.WriteFile(recipientPath, []byte(recipient.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, []byte(identity+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	pluginPath := filepath.Join(dir, "age-plugin-yubitouch")
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(testExecutable, pluginPath); err != nil {
		t.Fatal(err)
	}
	commandEnvironment := append(os.Environ(),
		pluginTestProcessEnvironment+"=1",
		"YUBITOUCH_CONFIG="+configPath,
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)

	// Recipient handling is entirely public and must work without a daemon.
	encrypt := exec.Command(agePath, "-R", recipientPath, "-o", ciphertextPath, plaintextPath)
	encrypt.Env = commandEnvironment
	if output, err := encrypt.CombinedOutput(); err != nil {
		t.Fatalf("offline age encryption failed: %v: %s", err, output)
	}

	writePluginTestConfig(t, dir, configPath, publicKey, time.Minute)
	listener, err := ageipc.Listen(filepath.Join(dir, "age.sock"))
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit Unix sockets")
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	server := &ageipc.Server{
		Handler: ageipc.HandlerFunc(func(_ context.Context, _ signing.Requester, request ageprofile.UnwrapRequest) ([]byte, ageipc.ErrorClass) {
			calls.Add(1)
			if request.ProfileID != recipient.ProfileID() || request.HardwareKeyID != recipient.Hardware().ID || request.Recovery != nil {
				return nil, ageipc.ClassInvalidRequest
			}
			fileKey, err := ageprofile.UnwrapWithPrivateKey(request.Hardware, privateKey)
			if err != nil {
				return nil, ageipc.ClassHardwareFailed
			}
			return fileKey, ""
		}),
		MaxConcurrent:  1,
		RequestTimeout: 5 * time.Second,
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx, listener) }()

	decrypt := exec.Command(agePath, "-d", "-i", identityPath, "-o", outputPath, ciphertextPath)
	decrypt.Env = commandEnvironment
	if output, err := decrypt.CombinedOutput(); err != nil {
		t.Fatalf("age plugin decryption failed: %v: %s", err, output)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted plaintext does not match")
	}
	if calls.Load() != 1 {
		t.Fatalf("daemon unwrap calls = %d, want 1", calls.Load())
	}

	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("age IPC server did not stop")
	}
}

func TestLazyAgeClientLoadsOnlyForMatchingUnwrap(t *testing.T) {
	configuredPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var configuredPublic ageprofile.PublicKey
	copy(configuredPublic[:], configuredPrivate.PublicKey().Bytes())
	otherPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var otherPublic ageprofile.PublicKey
	copy(otherPublic[:], otherPrivate.PublicKey().Bytes())

	var loads atomic.Int32
	var clients atomic.Int32
	var gotPath string
	var gotTimeout time.Duration
	lazy := &lazyAgeClient{
		home:       "/private/home",
		configPath: "/private/config.json",
		loadConfig: func(path, home string) (config.Config, error) {
			loads.Add(1)
			if path != "/private/config.json" || home != "/private/home" {
				t.Fatalf("load config arguments = %q, %q", path, home)
			}
			return config.Config{
				Age:           &config.AgeConfig{},
				AgeSocketPath: "/private/age.sock",
				SignTimeout:   config.Duration{Duration: 5 * time.Minute},
			}, nil
		},
		newClient: func(path string, timeout time.Duration) ageprofile.Client {
			clients.Add(1)
			gotPath = path
			gotTimeout = timeout
			return ageprofile.ClientFunc(func(_ context.Context, request ageprofile.UnwrapRequest) ([]byte, error) {
				return ageprofile.UnwrapWithPrivateKey(request.Hardware, configuredPrivate)
			})
		},
	}
	identity, err := ageprofile.NewIdentity(context.Background(), configuredPublic, lazy)
	if err != nil {
		t.Fatal(err)
	}

	otherRecipient, err := ageprofile.NewRecipient(otherPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := []byte("other-file-key!!")
	otherStanzas, err := otherRecipient.Wrap(otherKey)
	clear(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Unwrap(otherStanzas); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("non-matching unwrap error = %v", err)
	}
	if loads.Load() != 0 || clients.Load() != 0 {
		t.Fatalf("non-matching stanza loaded config or created client: loads=%d clients=%d", loads.Load(), clients.Load())
	}

	recipient, err := ageprofile.NewRecipient(configuredPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("matched-file-key")
	stanzas, err := recipient.Wrap(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity.Unwrap(stanzas)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if !bytes.Equal(got, want) {
		t.Fatalf("unwrapped file key = %x, want %x", got, want)
	}
	clear(want)
	if loads.Load() != 1 || clients.Load() != 1 {
		t.Fatalf("matching stanza lifecycle: loads=%d clients=%d", loads.Load(), clients.Load())
	}
	if gotPath != "/private/age.sock" || gotTimeout != 5*time.Minute+ageClientTimeoutMargin {
		t.Fatalf("client configuration = %q, %s", gotPath, gotTimeout)
	}
}

func TestLazyAgeClientRedactsConfigurationFailures(t *testing.T) {
	const sensitive = "op://Private/Vault/Item/Field serial=12345678"
	lazy := &lazyAgeClient{
		home:       "/private/home",
		configPath: "/private/config.json",
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{}, errors.New(sensitive)
		},
		newClient: func(string, time.Duration) ageprofile.Client {
			t.Fatal("configuration failure created an IPC client")
			return nil
		},
	}
	_, err := lazy.Unwrap(context.Background(), ageprofile.UnwrapRequest{})
	if class, ok := ageipc.ClassOf(err); !ok || class != ageipc.ClassConfiguration {
		t.Fatalf("error class = %q, %v", class, ok)
	}
	if strings.Contains(err.Error(), sensitive) || strings.Contains(err.Error(), "op://") || strings.Contains(err.Error(), "12345678") {
		t.Fatalf("configuration error leaked sensitive input: %v", err)
	}
}

func TestAgeClientTimeoutRejectsInvalidOrOverflowingDurations(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	for _, value := range []time.Duration{0, -time.Second, maxDuration - ageClientTimeoutMargin + 1} {
		if timeout, ok := ageClientTimeout(value); ok || timeout != 0 {
			t.Fatalf("ageClientTimeout(%s) = %s, %v", value, timeout, ok)
		}
	}
	if timeout, ok := ageClientTimeout(5 * time.Minute); !ok || timeout != 5*time.Minute+ageClientTimeoutMargin {
		t.Fatalf("long configured timeout = %s, %v", timeout, ok)
	}
}

func writePluginTestConfig(t *testing.T, home, configPath string, agePublic ageprofile.PublicKey, timeout time.Duration) {
	t.Helper()
	sshPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(sshPublic)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(home, "ssh.pub")
	if err := os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(publicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults(home)
	cfg.PublicKeyPath = publicKeyPath
	cfg.SignTimeout = config.Duration{Duration: timeout}
	cfg.Age = &config.AgeConfig{
		Serial:    "12345678",
		Slot:      "82",
		Algorithm: "x25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(agePublic[:]),
	}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "yt-age-plugin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
