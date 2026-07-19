package config

import (
	"bytes"
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
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	DefaultSound       = "Glass"
	DefaultSignTimeout = 60 * time.Second
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
	BackendSocketPath   string        `json:"backend_socket"`
	FallbackAgent       FallbackAgent `json:"fallback_agent,omitempty"`
	FallbackAgentSocket string        `json:"fallback_agent_socket,omitempty"`
	Sound               string        `json:"sound"`
	SignTimeout         Duration      `json:"sign_timeout"`
	LogLevel            string        `json:"log_level"`

	PublicKey ssh.PublicKey `json:"-"`
}

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
		BackendSocketPath: filepath.Join(runtimeDir, "backend.sock"),
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
	if err := cfg.ResolveAndValidate(home); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadForConfigure(path string, home string, getenv func(string) string) (Config, error) {
	if strings.TrimSpace(getenv("YUBITOUCH_PIN")) != "" {
		return Config{}, errors.New("YUBITOUCH_PIN is forbidden; PIN values must never be placed in the environment")
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
	if err := cfg.ResolveAndValidate(home); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
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
	if ok && int(stat.Uid) != os.Getuid() {
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
	c.BackendSocketPath = expandPath(c.BackendSocketPath, home)
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
	if c.FallbackAgent == FallbackAgentNone && c.FallbackAgentSocket != "" {
		return errors.New("fallback_agent_socket requires fallback_agent=1password")
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
	if c.LogLevel != "error" && c.LogLevel != "info" && c.LogLevel != "debug" {
		return fmt.Errorf("invalid log_level %q", c.LogLevel)
	}
	if c.SocketPath == c.BackendSocketPath {
		return errors.New("socket and backend_socket must be different")
	}
	if c.FallbackAgentSocket != "" && (c.FallbackAgentSocket == c.SocketPath || c.FallbackAgentSocket == c.BackendSocketPath) {
		return errors.New("fallback_agent_socket must be different from YubiTouch sockets")
	}
	// Darwin sockaddr_un.sun_path is 104 bytes including the terminator.
	if runtime.GOOS == "darwin" {
		if len(c.SocketPath) >= 104 {
			return fmt.Errorf("socket path is too long for macOS: %s", c.SocketPath)
		}
		if len(c.BackendSocketPath) >= 104 {
			return fmt.Errorf("backend_socket path is too long for macOS: %s", c.BackendSocketPath)
		}
		if len(c.FallbackAgentSocket) >= 104 {
			return fmt.Errorf("fallback_agent_socket path is too long for macOS: %s", c.FallbackAgentSocket)
		}
	}
	return nil
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
	setString("YUBITOUCH_BACKEND_SOCKET", &cfg.BackendSocketPath)
	if value := strings.TrimSpace(getenv("YUBITOUCH_FALLBACK_AGENT")); value != "" {
		switch strings.ToLower(value) {
		case "none", "off", "disabled":
			cfg.FallbackAgent = FallbackAgentNone
			cfg.FallbackAgentSocket = ""
		default:
			cfg.FallbackAgent = FallbackAgent(value)
		}
	}
	setString("YUBITOUCH_FALLBACK_AGENT_SOCKET", &cfg.FallbackAgentSocket)
	setString("YUBITOUCH_SOUND", &cfg.Sound)
	setString("YUBITOUCH_LOG_LEVEL", &cfg.LogLevel)
	if value := strings.TrimSpace(getenv("YUBITOUCH_SIGN_TIMEOUT")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.SignTimeout = Duration{Duration: parsed}
		} else {
			cfg.SignTimeout = Duration{}
		}
	}
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
