package agehelper

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mofelee/yubitouch/internal/config"
)

func TestStableConfigSnapshotBindsFileIdentity(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte("first snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := config.Config{PINProvider: config.PINProviderPrompt}
	loaded, first, err := loadStableConfigSnapshotWith(path, directory, func(string, string) (config.Config, error) {
		return want, nil
	}, os.Lstat)
	if err != nil || loaded.PINProvider != want.PINProvider || !validConfigSnapshotBinding(first) {
		t.Fatalf("snapshot config=%+v binding=%x err=%v", loaded, first, err)
	}

	replacement := filepath.Join(directory, "replacement.json")
	if err := os.WriteFile(replacement, []byte("second snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	_, second, err := loadStableConfigSnapshotWith(path, directory, func(string, string) (config.Config, error) {
		return want, nil
	}, os.Lstat)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("atomic replacement retained the previous snapshot binding")
	}
}

func TestStableConfigSnapshotRejectsReplacementDuringLoad(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte("first snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(directory, "replacement.json")
	if err := os.WriteFile(replacement, []byte("second snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, binding, err := loadStableConfigSnapshotWith(path, directory, func(string, string) (config.Config, error) {
		if renameErr := os.Rename(replacement, path); renameErr != nil {
			return config.Config{}, renameErr
		}
		return config.Config{}, nil
	}, os.Lstat)
	if err == nil || validConfigSnapshotBinding(binding) {
		t.Fatalf("replacement during load binding=%x err=%v", binding, err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot error exposed an unstable filesystem detail: %v", err)
	}
}

func TestConfigSnapshotBindingIncludesContentsWhenMetadataIsPreserved(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	firstContents := []byte("first snapshot")
	secondContents := []byte("other snapshot")
	if len(firstContents) != len(secondContents) {
		t.Fatal("content fixtures must have the same length")
	}
	if err := os.WriteFile(path, firstContents, 0o600); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	firstBinding, err := inspectConfigSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, secondContents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, beforeInfo.ModTime(), beforeInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(beforeInfo, afterInfo) || beforeInfo.Size() != afterInfo.Size() ||
		beforeInfo.Mode() != afterInfo.Mode() || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatalf("test rewrite changed bound metadata: before=%+v after=%+v", beforeInfo, afterInfo)
	}
	secondBinding, err := inspectConfigSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if firstBinding == secondBinding {
		t.Fatal("metadata-preserving content rewrite retained the previous snapshot binding")
	}
}

func TestStableConfigSnapshotRejectsMetadataPreservingRewriteDuringLoad(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	firstContents := []byte("first snapshot")
	secondContents := []byte("other snapshot")
	if err := os.WriteFile(path, firstContents, 0o600); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, binding, err := loadStableConfigSnapshotWith(path, directory, func(string, string) (config.Config, error) {
		if writeErr := os.WriteFile(path, secondContents, 0o600); writeErr != nil {
			return config.Config{}, writeErr
		}
		if timeErr := os.Chtimes(path, beforeInfo.ModTime(), beforeInfo.ModTime()); timeErr != nil {
			return config.Config{}, timeErr
		}
		return config.Config{}, nil
	}, os.Lstat)
	if err == nil || validConfigSnapshotBinding(binding) {
		t.Fatalf("metadata-preserving rewrite binding=%x err=%v", binding, err)
	}
}

func TestConfigSnapshotRejectsNonRegularFileBeforeReadingContents(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("sensitive target"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	readCalls := 0
	_, err := inspectStableConfigSnapshotWith(path, os.Lstat, func(string) ([]byte, error) {
		readCalls++
		return os.ReadFile(target)
	})
	if err == nil {
		t.Fatal("configuration snapshot accepted a symlink")
	}
	if readCalls != 0 {
		t.Fatalf("configuration snapshot read a non-regular path %d times", readCalls)
	}
}
