package agehelper

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"syscall"

	"github.com/mofelee/yubitouch/internal/config"
)

const configSnapshotBindingSize = sha256.Size

type configSnapshotBinding [configSnapshotBindingSize]byte

type configSnapshotLoader func(string, string) (config.Config, configSnapshotBinding, error)

func loadStableConfigSnapshot(path, home string) (config.Config, configSnapshotBinding, error) {
	return loadStableConfigSnapshotWith(path, home, config.Load, os.Lstat)
}

func inspectConfigSnapshot(path string) (configSnapshotBinding, error) {
	snapshot, err := inspectStableConfigSnapshotWith(path, os.Lstat, os.ReadFile)
	return snapshot.binding, err
}

func loadStableConfigSnapshotWith(
	path string,
	home string,
	load func(string, string) (config.Config, error),
	inspect func(string) (os.FileInfo, error),
) (config.Config, configSnapshotBinding, error) {
	if load == nil || inspect == nil {
		return config.Config{}, configSnapshotBinding{}, errors.New("configuration snapshot is unavailable")
	}
	before, err := inspectStableConfigSnapshotWith(path, inspect, os.ReadFile)
	if err != nil {
		return config.Config{}, configSnapshotBinding{}, errors.New("configuration snapshot is unavailable")
	}
	cfg, err := load(path, home)
	if err != nil {
		return config.Config{}, configSnapshotBinding{}, err
	}
	after, err := inspectStableConfigSnapshotWith(path, inspect, os.ReadFile)
	if err != nil {
		return config.Config{}, configSnapshotBinding{}, errors.New("configuration snapshot changed while loading")
	}
	if !os.SameFile(before.info, after.info) || before.binding != after.binding {
		return config.Config{}, configSnapshotBinding{}, errors.New("configuration snapshot changed while loading")
	}
	return cfg, after.binding, nil
}

type stableConfigSnapshot struct {
	info    os.FileInfo
	binding configSnapshotBinding
}

func inspectStableConfigSnapshotWith(
	path string,
	inspect func(string) (os.FileInfo, error),
	readFile func(string) ([]byte, error),
) (stableConfigSnapshot, error) {
	if inspect == nil || readFile == nil {
		return stableConfigSnapshot{}, errors.New("configuration snapshot is unavailable")
	}
	before, err := inspect(path)
	if err != nil {
		return stableConfigSnapshot{}, errors.New("configuration snapshot is unavailable")
	}
	if _, err := bindConfigFileSnapshot(before, [sha256.Size]byte{}); err != nil {
		return stableConfigSnapshot{}, err
	}
	contents, err := readFile(path)
	if err != nil {
		clear(contents)
		return stableConfigSnapshot{}, errors.New("configuration snapshot is unavailable")
	}
	contentDigest := sha256.Sum256(contents)
	clear(contents)
	defer clear(contentDigest[:])
	after, err := inspect(path)
	if err != nil {
		return stableConfigSnapshot{}, errors.New("configuration snapshot changed while reading")
	}
	beforeBinding, err := bindConfigFileSnapshot(before, contentDigest)
	if err != nil {
		return stableConfigSnapshot{}, err
	}
	afterBinding, err := bindConfigFileSnapshot(after, contentDigest)
	if err != nil || !os.SameFile(before, after) || beforeBinding != afterBinding {
		return stableConfigSnapshot{}, errors.New("configuration snapshot changed while reading")
	}
	return stableConfigSnapshot{info: after, binding: afterBinding}, nil
}

func bindConfigFileSnapshot(info os.FileInfo, contentDigest [sha256.Size]byte) (configSnapshotBinding, error) {
	if info == nil || !info.Mode().IsRegular() {
		return configSnapshotBinding{}, errors.New("configuration snapshot is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return configSnapshotBinding{}, errors.New("configuration snapshot is unavailable")
	}
	var metadata [40]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(stat.Dev))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(stat.Ino))
	binary.BigEndian.PutUint64(metadata[16:24], uint64(info.Size()))
	binary.BigEndian.PutUint64(metadata[24:32], uint64(info.Mode()))
	binary.BigEndian.PutUint64(metadata[32:40], uint64(info.ModTime().UnixNano()))
	hash := sha256.New()
	_, _ = hash.Write([]byte("yubitouch/config-snapshot/v2\x00"))
	_, _ = hash.Write(metadata[:])
	var binding configSnapshotBinding
	_, _ = hash.Write(contentDigest[:])
	copy(binding[:], hash.Sum(nil))
	clear(metadata[:])
	return binding, nil
}

func validConfigSnapshotBinding(binding configSnapshotBinding) bool {
	var combined byte
	for _, value := range binding {
		combined |= value
	}
	return combined != 0
}
