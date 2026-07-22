package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const (
	DefaultSound       = "Glass"
	DefaultSignTimeout = 60 * time.Second
	MaxSignTimeout     = time.Hour
	DefaultLogLevel    = "info"
)

type PINProvider string

const (
	PINProviderPrompt    PINProvider = "prompt"
	PINProvider1Password PINProvider = "1password"
)

type FallbackAgent string

const (
	FallbackAgentNone      FallbackAgent = ""
	FallbackAgent1Password FallbackAgent = "1password"
)

type Config struct {
	PINProvider         PINProvider   `json:"pin_provider"`
	OnePasswordAccount  string        `json:"onepassword_account,omitempty"`
	OnePasswordRef      string        `json:"onepassword_ref,omitempty"`
	PublicKeyPath       string        `json:"public_key"`
	YKCS11Path          string        `json:"ykcs11"`
	OpenSSHPrefix       string        `json:"openssh_prefix"`
	SocketPath          string        `json:"socket"`
	PIVSocketPath       string        `json:"piv_socket"`
	BackendSocketPath   string        `json:"backend_socket"`
	FallbackAgent       FallbackAgent `json:"fallback_agent,omitempty"`
	FallbackAgentSocket string        `json:"fallback_agent_socket,omitempty"`
	Sound               string        `json:"sound"`
	SignTimeout         Duration      `json:"sign_timeout"`
	LogLevel            string        `json:"log_level"`
	Age                 *AgeConfig    `json:"age,omitempty"`

	PublicKey     ssh.PublicKey `json:"-"`
	AgeSocketPath string        `json:"-"`
}

type AgeConfig struct {
	Serial    string       `json:"serial"`
	Slot      string       `json:"slot"`
	Algorithm string       `json:"algorithm"`
	PublicKey string       `json:"public_key,omitempty"`
	Recovery  *AgeRecovery `json:"recovery,omitempty"`
}

type AgeRecovery struct {
	Provider    string `json:"provider"`
	IdentityRef string `json:"identity_ref"`
	Recipient   string `json:"recipient"`
}

type AgeTarget struct {
	Serial    string
	Slot      string
	Algorithm string
}

var (
	ErrAgeConfigurationChanged = errors.New("age configuration changed while reading the hardware public key")
	ErrConfigurationWrite      = errors.New("configuration write failed")
	configProcessLock          sync.Mutex
)

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

// SignTimeoutWithMargin adds a protocol margin without allowing duration
// overflow. Callers still validate the configured timeout against
// MaxSignTimeout at the configuration boundary.
func SignTimeoutWithMargin(timeout, margin time.Duration) (time.Duration, bool) {
	const maxDuration = time.Duration(1<<63 - 1)
	if timeout <= 0 || margin < 0 || timeout > maxDuration-margin {
		return 0, false
	}
	return timeout + margin, true
}

func DefaultPath(home string) string {
	return filepath.Join(home, ".ssh", "yubitouch", "config.json")
}

func Defaults(home string) Config {
	runtimeDir := filepath.Join(home, ".ssh", "yubitouch")
	return Config{
		PINProvider:       PINProviderPrompt,
		OpenSSHPrefix:     defaultOpenSSHPrefix(),
		YKCS11Path:        defaultYKCS11Path(),
		SocketPath:        filepath.Join(runtimeDir, "agent.sock"),
		PIVSocketPath:     filepath.Join(runtimeDir, "piv-agent.sock"),
		BackendSocketPath: filepath.Join(runtimeDir, "backend.sock"),
		AgeSocketPath:     filepath.Join(runtimeDir, "age.sock"),
		Sound:             DefaultSound,
		SignTimeout:       Duration{Duration: DefaultSignTimeout},
		LogLevel:          DefaultLogLevel,
	}
}

func PathFromEnvironment(home string, getenv func(string) string) string {
	if value := strings.TrimSpace(getenv("YUBITOUCH_CONFIG")); value != "" {
		return expandPath(value, home)
	}
	return DefaultPath(home)
}

func Load(path string, home string) (Config, error) {
	cfg := Defaults(home)
	if err := validatePrivateDir(filepath.Dir(path)); err != nil {
		return Config{}, err
	}
	if err := validatePrivateFile(path); err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := decodeStrict(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	setAgeSocketPath(&cfg, path, home)
	if err := cfg.ResolveAndValidate(home); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadForConfigure(path string, home string, getenv func(string) string) (Config, error) {
	if strings.TrimSpace(getenv("YUBITOUCH_PIN")) != "" {
		return Config{}, errors.New("YUBITOUCH_PIN is forbidden; PIN values must never be placed in the environment")
	}
	for _, name := range []string{
		"YUBITOUCH_AGE_RECOVERY_IDENTITY",
		"YUBITOUCH_AGE_RECOVERY_PRIVATE_KEY",
		"YUBITOUCH_AGE_RECOVERY_SECRET",
	} {
		if strings.TrimSpace(getenv(name)) != "" {
			return Config{}, fmt.Errorf("%s is forbidden; recovery private keys must never be placed in the environment", name)
		}
	}
	cfg := Defaults(home)
	if err := validatePrivateFile(path); err == nil {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return Config{}, readErr
		}
		if err := decodeStrict(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Config{}, err
	}
	applyEnvironment(&cfg, getenv)
	setAgeSocketPath(&cfg, path, home)
	if err := cfg.ResolveAndValidate(home); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Configure serializes the read-modify-write sequence used by the configure
// command with other configuration writers.
func Configure(path string, home string, getenv func(string) string) (Config, error) {
	var cfg Config
	var loadFailed bool
	err := withConfigLock(path, func() error {
		loaded, err := LoadForConfigure(path, home, getenv)
		if err != nil {
			loadFailed = true
			return err
		}
		if err := saveUnlocked(path, loaded); err != nil {
			return fmt.Errorf("%w: %v", ErrConfigurationWrite, err)
		}
		cfg = loaded
		return nil
	})
	if err != nil && !loadFailed && !errors.Is(err, ErrConfigurationWrite) {
		err = fmt.Errorf("%w: %v", ErrConfigurationWrite, err)
	}
	return cfg, err
}

func Save(path string, cfg Config) error {
	return withConfigLock(path, func() error {
		return saveUnlocked(path, cfg)
	})
}

// CacheAgePublicKey updates only the cache field in the latest configuration.
// It fails closed if the hardware target changed while the key was being read.
func CacheAgePublicKey(path string, home string, expected AgeTarget, publicKey ageprofile.PublicKey) (Config, error) {
	var result Config
	err := withConfigLock(path, func() error {
		cfg, err := Load(path, home)
		if err != nil {
			return err
		}
		if cfg.Age == nil || cfg.Age.Serial != expected.Serial || cfg.Age.Slot != expected.Slot || cfg.Age.Algorithm != expected.Algorithm {
			return ErrAgeConfigurationChanged
		}

		encoded := base64.RawURLEncoding.EncodeToString(publicKey[:])
		if cfg.Age.PublicKey != "" && cfg.Age.PublicKey != encoded {
			return ErrAgeConfigurationChanged
		}
		if cfg.Age.PublicKey == "" {
			cfg.Age.PublicKey = encoded
			if err := cfg.resolveAndValidateAge(); err != nil {
				return err
			}
			if err := saveUnlocked(path, cfg); err != nil {
				return err
			}
		}
		result = cfg
		return nil
	})
	return result, err
}

func saveUnlocked(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func withConfigLock(path string, fn func() error) error {
	configProcessLock.Lock()
	defer configProcessLock.Unlock()

	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	lockPath := path + ".lock"
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("open configuration lock: %w", err)
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect configuration lock: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || int(stat.Uid) != os.Getuid() || stat.Mode&0o777 != 0o600 {
		return errors.New("configuration lock must be a 0600 regular file owned by the current user")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("lock configuration: %w", err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}

func EnsurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime directory must not be a symlink: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime path is not a directory: %s", path)
	}
	if err := validateOwner(info, path); err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateFile(path string) error {
	if err := validatePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("configuration must be a regular file, not a symlink: %s", path)
	}
	if err := validateOwner(info, path); err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("configuration permissions must be 0600, got %04o: %s", info.Mode().Perm(), path)
	}
	return nil
}

func validatePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("runtime directory must be a regular directory: %s", path)
	}
	if err := validateOwner(info, path); err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("runtime directory permissions must be 0700, got %04o: %s", info.Mode().Perm(), path)
	}
	return nil
}

func validateOwner(info fs.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("path is not owned by the current user: %s", path)
	}
	return nil
}

func (c *Config) ResolveAndValidate(home string) error {
	c.PublicKeyPath = expandPath(c.PublicKeyPath, home)
	c.OpenSSHPrefix = expandPath(c.OpenSSHPrefix, home)
	c.YKCS11Path = expandPath(c.YKCS11Path, home)
	c.YKCS11Path = stableYKCS11Path(c.YKCS11Path)
	c.SocketPath = expandPath(c.SocketPath, home)
	c.PIVSocketPath = expandPath(c.PIVSocketPath, home)
	c.BackendSocketPath = expandPath(c.BackendSocketPath, home)
	if strings.TrimSpace(c.AgeSocketPath) == "" {
		c.AgeSocketPath = filepath.Join(filepath.Dir(DefaultPath(home)), "age.sock")
	}
	c.AgeSocketPath = expandPath(c.AgeSocketPath, home)
	if c.FallbackAgent == FallbackAgent1Password && strings.TrimSpace(c.FallbackAgentSocket) == "" {
		c.FallbackAgentSocket = defaultOnePasswordAgentSocket(home)
	}
	c.FallbackAgentSocket = expandPath(c.FallbackAgentSocket, home)

	if c.PINProvider != PINProviderPrompt && c.PINProvider != PINProvider1Password {
		return fmt.Errorf("invalid pin_provider %q", c.PINProvider)
	}
	if c.PINProvider == PINProvider1Password {
		if strings.TrimSpace(c.OnePasswordAccount) == "" {
			return errors.New("onepassword_account is required for the 1password provider")
		}
		if !strings.HasPrefix(c.OnePasswordRef, "op://") {
			return errors.New("onepassword_ref must be an op:// secret reference")
		}
	}
	if c.FallbackAgent != FallbackAgentNone && c.FallbackAgent != FallbackAgent1Password {
		return fmt.Errorf("invalid fallback_agent %q", c.FallbackAgent)
	}
	if c.FallbackAgent == FallbackAgent1Password && c.FallbackAgentSocket == "" {
		return errors.New("fallback_agent_socket is required for the 1password fallback")
	}
	if strings.TrimSpace(c.PublicKeyPath) == "" {
		return errors.New("public_key is required")
	}
	key, err := readPublicKey(c.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("public_key: %w", err)
	}
	c.PublicKey = key
	if c.PublicKey.Type() != ssh.KeyAlgoED25519 {
		return fmt.Errorf("public_key must be an ssh-ed25519 PIV 9A key, got %s", c.PublicKey.Type())
	}
	if c.SignTimeout.Duration <= 0 {
		return errors.New("sign_timeout must be greater than zero")
	}
	if c.SignTimeout.Duration > MaxSignTimeout {
		return errors.New("sign_timeout must not exceed 1h")
	}
	if c.LogLevel != "error" && c.LogLevel != "info" && c.LogLevel != "debug" {
		return fmt.Errorf("invalid log_level %q", c.LogLevel)
	}
	if err := c.resolveAndValidateAge(); err != nil {
		return err
	}
	managed := []string{c.SocketPath, c.PIVSocketPath, c.BackendSocketPath}
	if c.Age != nil {
		managed = append(managed, c.AgeSocketPath)
	}
	for i := range managed {
		if strings.TrimSpace(managed[i]) == "" {
			return errors.New("socket, piv_socket, backend_socket, and age socket are required")
		}
		for j := 0; j < i; j++ {
			if managed[i] == managed[j] {
				return errors.New("socket, piv_socket, backend_socket, and age socket must be different")
			}
		}
	}
	if c.FallbackAgentSocket != "" {
		for _, path := range managed {
			if c.FallbackAgentSocket == path {
				return errors.New("fallback_agent_socket must be different from YubiTouch sockets")
			}
		}
	}
	// Darwin sockaddr_un.sun_path is 104 bytes including the terminator.
	if runtime.GOOS == "darwin" {
		if len(c.SocketPath) >= 104 {
			return fmt.Errorf("socket path is too long for macOS: %s", c.SocketPath)
		}
		if len(c.PIVSocketPath) >= 104 {
			return fmt.Errorf("piv_socket path is too long for macOS: %s", c.PIVSocketPath)
		}
		if len(c.BackendSocketPath) >= 104 {
			return fmt.Errorf("backend_socket path is too long for macOS: %s", c.BackendSocketPath)
		}
		if c.Age != nil && len(c.AgeSocketPath) >= 104 {
			return fmt.Errorf("age socket path is too long for macOS: %s", c.AgeSocketPath)
		}
		if len(c.FallbackAgentSocket) >= 104 {
			return fmt.Errorf("fallback_agent_socket path is too long for macOS: %s", c.FallbackAgentSocket)
		}
	}
	return nil
}

func (c *Config) resolveAndValidateAge() error {
	if c.Age == nil {
		return nil
	}
	serial := c.Age.Serial
	parsedSerial, err := strconv.ParseUint(serial, 10, 32)
	if err != nil || parsedSerial == 0 || strconv.FormatUint(parsedSerial, 10) != serial {
		return errors.New("age.serial must be a canonical non-zero uint32")
	}

	slot := strings.ToLower(strings.TrimSpace(c.Age.Slot))
	if !validAgeSlot(slot) {
		return fmt.Errorf("invalid age.slot %q", c.Age.Slot)
	}
	c.Age.Slot = slot
	if c.Age.Algorithm != "x25519" {
		return fmt.Errorf("invalid age.algorithm %q; only x25519 is supported", c.Age.Algorithm)
	}
	var hardwarePublicKey *ageprofile.PublicKey
	if c.Age.PublicKey != "" {
		publicKey, err := base64.RawURLEncoding.DecodeString(c.Age.PublicKey)
		if err != nil || len(publicKey) != 32 || base64.RawURLEncoding.EncodeToString(publicKey) != c.Age.PublicKey {
			return errors.New("age.public_key must be canonical unpadded base64url encoding of 32 bytes")
		}
		var key ageprofile.PublicKey
		copy(key[:], publicKey)
		if _, err := ageprofile.NewRecipient(key, nil); err != nil {
			return errors.New("age.public_key must encode a valid canonical X25519 public key")
		}
		hardwarePublicKey = &key
	}
	if c.Age.Recovery == nil {
		return nil
	}

	recovery := c.Age.Recovery
	if recovery.Provider != "1password" {
		return fmt.Errorf("invalid age.recovery.provider %q; only 1password is supported", recovery.Provider)
	}
	if strings.TrimSpace(c.OnePasswordAccount) == "" {
		return errors.New("onepassword_account is required for age recovery")
	}
	if err := ValidateAgeRecoveryIdentityReference(context.Background(), recovery.IdentityRef); err != nil {
		return err
	}
	recoveryPublicKey, err := ageprofile.ParseNativeRecipient(recovery.Recipient)
	if err != nil {
		return errors.New("age.recovery.recipient must be a canonical native age X25519 recipient")
	}
	if hardwarePublicKey != nil {
		if _, err := ageprofile.NewRecipient(*hardwarePublicKey, &recoveryPublicKey); err != nil {
			return errors.New("age.public_key and age.recovery.recipient must use independent X25519 public keys")
		}
	}
	return nil
}

// ValidateAgeRecoveryIdentityReference validates syntax only. It never resolves
// the referenced recovery identity and intentionally discards SDK error details.
func ValidateAgeRecoveryIdentityReference(ctx context.Context, reference string) error {
	if strings.TrimSpace(reference) != reference {
		return errors.New("age.recovery.identity_ref must be a valid 1Password secret reference")
	}
	if err := onepassword.Secrets.ValidateSecretReference(ctx, reference); err != nil {
		return errors.New("age.recovery.identity_ref must be a valid 1Password secret reference")
	}
	return nil
}

func validAgeSlot(slot string) bool {
	switch slot {
	case "9a", "9c", "9d", "9e":
		return true
	}
	if len(slot) != 2 {
		return false
	}
	value, err := strconv.ParseUint(slot, 16, 8)
	return err == nil && value >= 0x82 && value <= 0x95
}

func (c Config) Fingerprint() string {
	if c.PublicKey == nil {
		return ""
	}
	return ssh.FingerprintSHA256(c.PublicKey)
}

func decodeStrict(data []byte, cfg *Config) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("config contains multiple JSON values")
		}
		return err
	}
	return nil
}

func applyEnvironment(cfg *Config, getenv func(string) string) {
	setString := func(name string, target *string) {
		if value := strings.TrimSpace(getenv(name)); value != "" {
			*target = value
		}
	}
	if value := strings.TrimSpace(getenv("YUBITOUCH_PIN_PROVIDER")); value != "" {
		cfg.PINProvider = PINProvider(value)
	}
	setString("YUBITOUCH_1PASSWORD_ACCOUNT", &cfg.OnePasswordAccount)
	setString("YUBITOUCH_1PASSWORD_REF", &cfg.OnePasswordRef)
	setString("YUBITOUCH_PUBLIC_KEY", &cfg.PublicKeyPath)
	setString("YUBITOUCH_YKCS11", &cfg.YKCS11Path)
	setString("YUBITOUCH_OPENSSH_PREFIX", &cfg.OpenSSHPrefix)
	setString("YUBITOUCH_SOCKET", &cfg.SocketPath)
	setString("YUBITOUCH_PIV_SOCKET", &cfg.PIVSocketPath)
	setString("YUBITOUCH_BACKEND_SOCKET", &cfg.BackendSocketPath)
	if value := strings.TrimSpace(getenv("YUBITOUCH_FALLBACK_AGENT")); value != "" {
		switch strings.ToLower(value) {
		case "none", "off", "disabled":
			cfg.FallbackAgent = FallbackAgentNone
		default:
			cfg.FallbackAgent = FallbackAgent(value)
		}
	}
	setString("YUBITOUCH_FALLBACK_AGENT_SOCKET", &cfg.FallbackAgentSocket)
	setString("YUBITOUCH_SOUND", &cfg.Sound)
	setString("YUBITOUCH_LOG_LEVEL", &cfg.LogLevel)
	ageValues := map[string]string{
		"serial":                strings.TrimSpace(getenv("YUBITOUCH_AGE_SERIAL")),
		"slot":                  strings.TrimSpace(getenv("YUBITOUCH_AGE_SLOT")),
		"algorithm":             strings.TrimSpace(getenv("YUBITOUCH_AGE_ALGORITHM")),
		"recovery_provider":     strings.TrimSpace(getenv("YUBITOUCH_AGE_RECOVERY_PROVIDER")),
		"recovery_identity_ref": strings.TrimSpace(getenv("YUBITOUCH_AGE_RECOVERY_IDENTITY_REF")),
		"recovery_recipient":    strings.TrimSpace(getenv("YUBITOUCH_AGE_RECOVERY_RECIPIENT")),
	}
	if ageValues["serial"] != "" || ageValues["slot"] != "" || ageValues["algorithm"] != "" ||
		ageValues["recovery_provider"] != "" || ageValues["recovery_identity_ref"] != "" || ageValues["recovery_recipient"] != "" {
		if cfg.Age == nil {
			cfg.Age = &AgeConfig{}
		}
		targetChanged := false
		if ageValues["serial"] != "" {
			targetChanged = targetChanged || cfg.Age.Serial != ageValues["serial"]
			cfg.Age.Serial = ageValues["serial"]
		}
		if ageValues["slot"] != "" {
			targetChanged = targetChanged || !strings.EqualFold(cfg.Age.Slot, ageValues["slot"])
			cfg.Age.Slot = ageValues["slot"]
		}
		if ageValues["algorithm"] != "" {
			targetChanged = targetChanged || cfg.Age.Algorithm != ageValues["algorithm"]
			cfg.Age.Algorithm = ageValues["algorithm"]
		}
		if targetChanged {
			cfg.Age.PublicKey = ""
		}
		if ageValues["recovery_provider"] != "" || ageValues["recovery_identity_ref"] != "" || ageValues["recovery_recipient"] != "" {
			if cfg.Age.Recovery == nil {
				cfg.Age.Recovery = &AgeRecovery{}
			}
			if ageValues["recovery_provider"] != "" {
				cfg.Age.Recovery.Provider = ageValues["recovery_provider"]
			}
			if ageValues["recovery_identity_ref"] != "" {
				cfg.Age.Recovery.IdentityRef = ageValues["recovery_identity_ref"]
			}
			if ageValues["recovery_recipient"] != "" {
				cfg.Age.Recovery.Recipient = ageValues["recovery_recipient"]
			}
		}
	}
	if value := strings.TrimSpace(getenv("YUBITOUCH_SIGN_TIMEOUT")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.SignTimeout = Duration{Duration: parsed}
		} else {
			cfg.SignTimeout = Duration{}
		}
	}
}

func setAgeSocketPath(cfg *Config, configPath string, home string) {
	path := expandPath(configPath, home)
	cfg.AgeSocketPath = filepath.Join(filepath.Dir(path), "age.sock")
}

func readPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("file must contain exactly one public key")
	}
	return key, nil
}

func expandPath(value string, home string) string {
	if value == "~" {
		return home
	}
	if strings.HasPrefix(value, "~/") {
		return filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return filepath.Clean(value)
	}
	return abs
}

func defaultOpenSSHPrefix() string {
	candidates := []string{"/opt/homebrew/opt/openssh", "/usr/local/opt/openssh"}
	if runtime.GOARCH == "amd64" {
		candidates[0], candidates[1] = candidates[1], candidates[0]
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(filepath.Join(candidate, "bin", "ssh-agent")); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return candidates[0]
}

func defaultYKCS11Path() string {
	candidates := []string{
		"/opt/homebrew/opt/yubico-piv-tool/lib/libykcs11.dylib",
		"/usr/local/opt/yubico-piv-tool/lib/libykcs11.dylib",
	}
	if runtime.GOARCH == "amd64" {
		candidates[0], candidates[1] = candidates[1], candidates[0]
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return candidates[0]
}

func defaultOnePasswordAgentSocket(home string) string {
	return filepath.Join(home, "Library", "Group Containers", "2BUA8C4S2C.com.1password", "t", "agent.sock")
}

func stableYKCS11Path(path string) string {
	for _, prefix := range []string{"/opt/homebrew", "/usr/local"} {
		cellar := filepath.Join(prefix, "Cellar", "yubico-piv-tool")
		relative, err := filepath.Rel(cellar, path)
		if err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.Join(prefix, "opt", "yubico-piv-tool", "lib", "libykcs11.dylib")
		}
	}
	return path
}

func ParseBoolEnvironment(getenv func(string) string, name string) bool {
	value, _ := strconv.ParseBool(strings.TrimSpace(getenv(name)))
	return value
}
