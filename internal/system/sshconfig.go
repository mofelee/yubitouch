package system

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type SSHConfigReport struct {
	Exists          bool
	UsesPublicAgent bool
	UsesBackend     bool
	HasMatchExec    bool
}

func InspectSSHConfig(path string, home string, publicSocket string, backendSocket string) (SSHConfigReport, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return SSHConfigReport{}, nil
	}
	if err != nil {
		return SSHConfigReport{}, err
	}
	defer file.Close()

	report := SSHConfigReport{Exists: true}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		switch directive {
		case "identityagent":
			value := normalizeSSHPath(fields[1], home)
			report.UsesPublicAgent = report.UsesPublicAgent || value == filepath.Clean(publicSocket)
			report.UsesBackend = report.UsesBackend || value == filepath.Clean(backendSocket)
		case "match":
			lower := strings.ToLower(line)
			if strings.Contains(lower, "exec") && strings.Contains(lower, "yubitouch") {
				report.HasMatchExec = true
			}
		}
	}
	return report, scanner.Err()
}

func normalizeSSHPath(value string, home string) string {
	value = strings.Trim(value, "\"")
	value = strings.ReplaceAll(value, "%d", home)
	if value == "~" {
		return home
	}
	if strings.HasPrefix(value, "~/") {
		return filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	return filepath.Clean(value)
}
