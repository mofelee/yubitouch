package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mofelee/yubitouch/internal/config"
	"golang.org/x/crypto/ssh"
)

type HardwareReport struct {
	DeviceCount       int
	SlotAlgorithm     string
	PINPolicy         string
	TouchPolicy       string
	TargetKeyFound    bool
	OtherProviderKeys int
}

func InspectHardware(ctx context.Context, cfg config.Config, deps Dependencies) (HardwareReport, error) {
	ykman, err := exec.LookPath("ykman")
	if err != nil {
		return HardwareReport{}, errors.New("ykman is not installed")
	}
	serialOutput, err := exec.CommandContext(ctx, ykman, "list", "--serials").Output()
	if err != nil {
		return HardwareReport{}, fmt.Errorf("cannot query connected YubiKeys: %w", err)
	}
	report := HardwareReport{DeviceCount: countNonEmptyLines(serialOutput)}
	if report.DeviceCount == 0 {
		return report, errors.New("no YubiKey was detected")
	}

	metadata, err := exec.CommandContext(ctx, ykman, "piv", "keys", "info", "9a").Output()
	if err != nil {
		return report, fmt.Errorf("cannot inspect PIV slot 9A: %w", err)
	}
	fields := parseMetadata(metadata)
	report.SlotAlgorithm = fields["Algorithm"]
	report.PINPolicy = fields["PIN required for use"]
	report.TouchPolicy = fields["Touch required for use"]

	providerOutput, err := exec.CommandContext(ctx, deps.SSHKeygen, "-D", deps.YKCS11).Output()
	if err != nil {
		return report, fmt.Errorf("cannot enumerate YKCS11 public keys: %w", err)
	}
	report.TargetKeyFound, report.OtherProviderKeys = inspectProviderKeys(providerOutput, cfg.PublicKey)
	return report, nil
}

func inspectProviderKeys(output []byte, target ssh.PublicKey) (bool, int) {
	found := false
	other := 0
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		if target != nil && bytes.Equal(key.Marshal(), target.Marshal()) {
			found = true
		} else {
			other++
		}
	}
	return found, other
}

func parseMetadata(output []byte) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return fields
}

func countNonEmptyLines(output []byte) int {
	count := 0
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) != 0 {
			count++
		}
	}
	return count
}
