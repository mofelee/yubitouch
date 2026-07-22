package clientidentity

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/mofelee/yubitouch/internal/signing"
)

const (
	unknownRequester = "未知程序"
	maxDisplayRunes  = 64
)

type bundleMetadata struct {
	name       string
	identifier string
	verified   bool
}

type processSnapshot struct {
	executable string
	path       string
	bundle     bundleMetadata
}

func chooseRequester(chain []processSnapshot) signing.Requester {
	if len(chain) == 0 {
		return signing.Requester{Name: unknownRequester}
	}
	direct := friendlyExecutable(chain[0].executable)
	if direct == "" {
		direct = unknownRequester
	}

	if strings.EqualFold(chain[0].executable, "yubitouch") {
		return requesterFromProcess(chain[0], "YubiTouch", direct)
	}
	for _, process := range chain {
		if isDebianForm(process.executable) {
			return signing.Requester{Name: "DebianForm", DirectClient: direct}
		}
	}

	for _, process := range chain {
		if process.bundle.verified && process.bundle.name != "" {
			return requesterFromProcess(process, process.bundle.name, direct)
		}
	}
	for _, process := range chain {
		if process.bundle.name != "" {
			return requesterFromProcess(process, process.bundle.name, direct)
		}
	}
	for _, process := range chain {
		if !isGenericProcess(process.executable) {
			if name := friendlyExecutable(process.executable); name != "" {
				return signing.Requester{Name: name, DirectClient: direct}
			}
		}
	}
	return signing.Requester{Name: direct, DirectClient: direct}
}

func requesterFromProcess(process processSnapshot, name string, direct string) signing.Requester {
	requester := signing.Requester{
		Name:           sanitizeDisplay(name),
		DirectClient:   sanitizeDisplay(direct),
		VerifiedBundle: process.bundle.verified,
	}
	if requester.Name == "" {
		requester.Name = unknownRequester
	}
	if process.bundle.verified || requester.Name == "YubiTouch" {
		requester.BundleIdentifier = sanitizeBundleIdentifier(process.bundle.identifier)
	}
	return requester
}

func friendlyExecutable(value string) string {
	name := strings.TrimSuffix(filepath.Base(strings.TrimSpace(value)), ".app")
	switch strings.ToLower(name) {
	case "dbf", "debianform":
		return "DebianForm"
	case "yubitouch":
		return "YubiTouch"
	default:
		return sanitizeDisplay(name)
	}
}

func isDebianForm(value string) bool {
	switch strings.ToLower(filepath.Base(strings.TrimSpace(value))) {
	case "dbf", "debianform":
		return true
	default:
		return false
	}
}

func isGenericProcess(value string) bool {
	switch strings.ToLower(filepath.Base(strings.TrimSpace(value))) {
	case "", "ssh", "ssh-add", "ssh-agent", "age", "age-plugin-yubitouch", "git", "git-remote-ssh", "sh", "bash", "dash", "zsh", "fish", "env", "login", "xcrun", "open":
		return true
	default:
		return false
	}
}

func sanitizeDisplay(value string) string {
	filtered := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	filtered = strings.Join(strings.Fields(filtered), " ")
	runes := []rune(filtered)
	if len(runes) > maxDisplayRunes {
		filtered = string(runes[:maxDisplayRunes])
	}
	return filtered
}

func sanitizeBundleIdentifier(value string) string {
	value = strings.TrimSpace(value)
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' {
			continue
		}
		return ""
	}
	return value
}

func enclosingBundle(path string) string {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, volume)
	rooted := strings.HasPrefix(rest, string(filepath.Separator))
	parts := strings.Split(strings.TrimPrefix(rest, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		if !strings.HasSuffix(strings.ToLower(part), ".app") {
			continue
		}
		bundle := filepath.Join(parts[:index+1]...)
		if rooted {
			bundle = string(filepath.Separator) + bundle
		}
		return volume + bundle
	}
	return ""
}
