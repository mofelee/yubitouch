package agentroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mofelee/yubitouch/internal/config"
)

const (
	guardVersion  = 1
	guardFileName = "route-guard.json"
	maxGuardSize  = 16 * 1024
)

type routeGuard struct {
	Version        int    `json:"version"`
	PublicSocket   string `json:"public_socket"`
	PIVSocket      string `json:"piv_socket"`
	FallbackSocket string `json:"fallback_socket,omitempty"`
}

func GuardPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), guardFileName)
}

// FailClosedFromGuard does not parse the main configuration, so it can remove
// an unattended fallback route even when that configuration is invalid.
func FailClosedFromGuard(path string) error {
	record, err := readGuard(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return failClosedGuard(record)
}

func ValidateGuard(path string, cfg config.Config) error {
	record, err := readGuard(path)
	if err != nil {
		return err
	}
	expected, err := guardForConfig(cfg)
	if err != nil {
		return err
	}
	if record != expected {
		return errors.New("route guard does not match the current configuration")
	}
	return nil
}

func guardForConfig(cfg config.Config) (routeGuard, error) {
	publicPath, err := absolutePath(cfg.SocketPath)
	if err != nil {
		return routeGuard{}, fmt.Errorf("public socket: %w", err)
	}
	pivPath, err := absolutePath(cfg.PIVSocketPath)
	if err != nil {
		return routeGuard{}, fmt.Errorf("PIV socket: %w", err)
	}
	record := routeGuard{
		Version:      guardVersion,
		PublicSocket: publicPath,
		PIVSocket:    pivPath,
	}
	if cfg.FallbackAgent == config.FallbackAgent1Password {
		fallbackPath, pathErr := absolutePath(cfg.FallbackAgentSocket)
		if pathErr != nil {
			return routeGuard{}, fmt.Errorf("fallback socket: %w", pathErr)
		}
		record.FallbackSocket = fallbackPath
	}
	if err := record.validate(); err != nil {
		return routeGuard{}, err
	}
	return record, nil
}

func persistGuard(path string, cfg config.Config) error {
	record, err := guardForConfig(cfg)
	if err != nil {
		return err
	}
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("route guard parent: %w", err)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	temp, err := os.CreateTemp(filepath.Dir(path), ".route-guard-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func readGuard(path string) (routeGuard, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return routeGuard{}, err
	}
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return routeGuard{}, fmt.Errorf("route guard parent: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return routeGuard{}, errors.New("route guard must be a regular file")
	}
	if !ownedByCurrentUser(info) {
		return routeGuard{}, errors.New("route guard is not owned by the current user")
	}
	if info.Mode().Perm() != 0o600 {
		return routeGuard{}, fmt.Errorf("route guard permissions must be 0600, got %04o", info.Mode().Perm())
	}
	if info.Size() > maxGuardSize {
		return routeGuard{}, errors.New("route guard is too large")
	}

	file, err := os.Open(path)
	if err != nil {
		return routeGuard{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return routeGuard{}, err
	}
	if !os.SameFile(info, openedInfo) || openedInfo.Mode().Perm() != 0o600 || !ownedByCurrentUser(openedInfo) {
		return routeGuard{}, errors.New("route guard changed while it was being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxGuardSize+1))
	if err != nil {
		return routeGuard{}, err
	}
	if len(data) > maxGuardSize {
		return routeGuard{}, errors.New("route guard is too large")
	}

	var record routeGuard
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return routeGuard{}, fmt.Errorf("read route guard: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return routeGuard{}, errors.New("route guard contains multiple JSON values")
		}
		return routeGuard{}, fmt.Errorf("read route guard: %w", err)
	}
	if err := record.validate(); err != nil {
		return routeGuard{}, err
	}
	return record, nil
}

func (g routeGuard) validate() error {
	if g.Version != guardVersion {
		return fmt.Errorf("unsupported route guard version %d", g.Version)
	}
	if err := validateGuardPath("public socket", g.PublicSocket, false); err != nil {
		return err
	}
	if err := validateGuardPath("PIV socket", g.PIVSocket, false); err != nil {
		return err
	}
	if err := validateGuardPath("fallback socket", g.FallbackSocket, true); err != nil {
		return err
	}
	if g.PublicSocket == g.PIVSocket || (g.FallbackSocket != "" && (g.FallbackSocket == g.PublicSocket || g.FallbackSocket == g.PIVSocket)) {
		return errors.New("route guard socket paths must be distinct")
	}
	return nil
}

func validateGuardPath(name string, path string, allowEmpty bool) error {
	if path == "" && allowEmpty {
		return nil
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("route guard %s path is invalid", name)
	}
	return nil
}

func failClosedGuard(record routeGuard) error {
	if record.FallbackSocket == "" {
		return nil
	}
	current, err := resolvedLinkTarget(record.PublicSocket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		info, statErr := os.Lstat(record.PublicSocket)
		if errors.Is(statErr, fs.ErrNotExist) {
			return nil
		}
		if statErr == nil && info.Mode()&os.ModeSymlink == 0 {
			return nil
		}
		return err
	}
	if current != record.FallbackSocket {
		return nil
	}
	if safeFailClosedTarget(record.PIVSocket, record.FallbackSocket) {
		return atomicRoute(record.PublicSocket, record.PIVSocket, record.FallbackSocket)
	}
	return removeRecordedFallback(record.PublicSocket, record.FallbackSocket)
}

func safeFailClosedTarget(path string, managedPaths ...string) bool {
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return false
	}
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return err == nil && validateSocket(path, managedPaths...) == nil
}

func removeRecordedFallback(publicPath string, fallbackPath string) error {
	if err := validatePrivateDirectory(filepath.Dir(publicPath)); err != nil {
		return fmt.Errorf("public agent parent: %w", err)
	}
	info, err := os.Lstat(publicPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 || !ownedByCurrentUser(info) {
		return errors.New("public agent path changed before fallback removal")
	}
	target, err := resolvedLinkTarget(publicPath)
	if err != nil {
		return err
	}
	if target != filepath.Clean(fallbackPath) {
		return errors.New("public agent route changed before fallback removal")
	}
	return os.Remove(publicPath)
}

func absolutePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
