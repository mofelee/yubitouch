package system

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type SSHConfigReport struct {
	Exists                       bool
	UsesPublicAgent              bool
	UsesPIVAgent                 bool
	UsesBackend                  bool
	UsesPublicIdentityFile       bool
	UsesIdentitiesOnly           bool
	UsesSafePublicIdentityConfig bool
	HasMatchExec                 bool
}

type SSHConfigTargets struct {
	PublicAgentSocket  string
	PIVAgentSocket     string
	BackendAgentSocket string
	PublicIdentityFile string
}

func InspectSSHConfig(path string, home string, publicSocket string, backendSocket string) (SSHConfigReport, error) {
	return InspectSSHConfigWithTargets(path, home, SSHConfigTargets{
		PublicAgentSocket:  publicSocket,
		BackendAgentSocket: backendSocket,
	})
}

func InspectSSHConfigWithTargets(path string, home string, targets SSHConfigTargets) (SSHConfigReport, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return SSHConfigReport{}, err
	}
	_, err = os.Stat(absolutePath)
	if errors.Is(err, fs.ErrNotExist) {
		return SSHConfigReport{}, nil
	}
	if err != nil {
		return SSHConfigReport{}, err
	}

	inspector := sshConfigInspector{
		home:        home,
		includeBase: filepath.Dir(absolutePath),
		targets:     targets,
		report:      SSHConfigReport{Exists: true},
		block:       sshConfigBlock{kind: sshConfigBlockGlobal},
		stack:       make(map[string]bool),
	}
	if err := inspector.inspectFile(absolutePath, 0); err != nil {
		inspector.report.UsesSafePublicIdentityConfig = false
		return inspector.report, err
	}
	if err := inspector.finishBlock(); err != nil {
		inspector.report.UsesSafePublicIdentityConfig = false
		return inspector.report, err
	}
	return inspector.report, nil
}

type sshConfigBlockKind uint8

const (
	sshConfigBlockGlobal sshConfigBlockKind = iota
	sshConfigBlockHost
	sshConfigBlockMatch
)

type sshConfigBlock struct {
	kind                  sshConfigBlockKind
	hostPatterns          []string
	identityAgentSet      bool
	identityAgentIsPublic bool
	identitiesOnlySet     bool
	identitiesOnlyIsYes   bool
	hasPublicIdentityFile bool
}

type sshConfigInspector struct {
	home        string
	includeBase string
	targets     SSHConfigTargets
	report      SSHConfigReport
	block       sshConfigBlock
	blocks      []sshConfigBlock
	stack       map[string]bool
}

func (i *sshConfigInspector) inspectFile(path string, depth int) error {
	if depth >= 32 {
		return fmt.Errorf("SSH config include depth exceeds 32 at %s", path)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve SSH config %s: %w", path, err)
	}
	realPath, err = filepath.Abs(realPath)
	if err != nil {
		return fmt.Errorf("resolve SSH config %s: %w", path, err)
	}
	if i.stack[realPath] {
		return fmt.Errorf("SSH config include cycle at %s", realPath)
	}
	i.stack[realPath] = true
	defer delete(i.stack, realPath)

	file, err := os.Open(realPath)
	if err != nil {
		return fmt.Errorf("open SSH config %s: %w", realPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		directive, remainder, ok := splitSSHDirective(line)
		if !ok {
			continue
		}
		if directive == "include" {
			patterns, err := sshArguments(remainder)
			if err != nil || len(patterns) == 0 {
				if err == nil {
					err = errors.New("no include pattern")
				}
				return fmt.Errorf("parse Include in %s: %w", realPath, err)
			}
			for _, pattern := range patterns {
				if err := i.inspectInclude(pattern, realPath, depth+1); err != nil {
					return err
				}
			}
			continue
		}

		arguments, err := sshArguments(remainder)
		if err != nil || len(arguments) == 0 {
			if err == nil {
				err = errors.New("missing argument")
			}
			return fmt.Errorf("parse %s in %s: %w", directive, realPath, err)
		}
		argument := arguments[0]
		switch directive {
		case "host":
			if err := validateHostPatterns(arguments); err != nil {
				return fmt.Errorf("parse Host in %s: %w", realPath, err)
			}
			if err := i.finishBlock(); err != nil {
				return err
			}
			i.block = sshConfigBlock{kind: sshConfigBlockHost, hostPatterns: arguments}
		case "match":
			if err := i.finishBlock(); err != nil {
				return err
			}
			i.block = sshConfigBlock{kind: sshConfigBlockMatch}
			lower := strings.ToLower(line)
			if strings.Contains(lower, "exec") && strings.Contains(lower, "yubitouch") {
				i.report.HasMatchExec = true
			}
		case "identityagent":
			isPublic := sshPathsEqual(argument, i.targets.PublicAgentSocket, i.home)
			i.report.UsesPublicAgent = i.report.UsesPublicAgent || isPublic
			i.report.UsesPIVAgent = i.report.UsesPIVAgent || sshPathsEqual(argument, i.targets.PIVAgentSocket, i.home)
			i.report.UsesBackend = i.report.UsesBackend || sshPathsEqual(argument, i.targets.BackendAgentSocket, i.home)
			if !i.block.identityAgentSet {
				i.block.identityAgentSet = true
				i.block.identityAgentIsPublic = isPublic
			}
		case "identityfile":
			isPublic := sshPathsEqual(argument, i.targets.PublicIdentityFile, i.home)
			i.report.UsesPublicIdentityFile = i.report.UsesPublicIdentityFile || isPublic
			i.block.hasPublicIdentityFile = i.block.hasPublicIdentityFile || isPublic
		case "identitiesonly":
			isYes := strings.EqualFold(argument, "yes")
			i.report.UsesIdentitiesOnly = i.report.UsesIdentitiesOnly || isYes
			if !i.block.identitiesOnlySet {
				i.block.identitiesOnlySet = true
				i.block.identitiesOnlyIsYes = isYes
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read SSH config %s: %w", realPath, err)
	}
	return nil
}

func (i *sshConfigInspector) inspectInclude(pattern string, includingFile string, depth int) error {
	pattern = strings.ReplaceAll(pattern, "%d", i.home)
	if pattern == "~" {
		pattern = i.home
	} else if strings.HasPrefix(pattern, "~/") {
		pattern = filepath.Join(i.home, strings.TrimPrefix(pattern, "~/"))
	} else if strings.HasPrefix(pattern, "~") {
		return fmt.Errorf("inspect SSH config Include %q in %s: named home directories are not supported", pattern, includingFile)
	} else if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(i.includeBase, pattern)
	}
	if strings.ContainsAny(pattern, "$%") {
		return fmt.Errorf("inspect SSH config Include %q in %s: unresolved expansion", pattern, includingFile)
	}

	matches, err := globWithErrors(pattern)
	if err != nil {
		return fmt.Errorf("expand SSH config Include %q: %w", pattern, err)
	}
	for _, match := range matches {
		if err := i.inspectFile(match, depth); err != nil {
			return err
		}
	}
	return nil
}

func (i *sshConfigInspector) finishBlock() error {
	block := i.block
	defer func() {
		i.blocks = append(i.blocks, block)
	}()

	locallySafe := block.kind != sshConfigBlockMatch &&
		block.identityAgentSet && block.identityAgentIsPublic &&
		block.hasPublicIdentityFile &&
		block.identitiesOnlySet && block.identitiesOnlyIsYes
	if !locallySafe {
		return nil
	}
	if block.kind == sshConfigBlockGlobal {
		i.report.UsesSafePublicIdentityConfig = true
		return nil
	}

	candidates := literalHostCandidates(block)
	if len(candidates) == 0 {
		return nil
	}
	for _, candidate := range candidates {
		safe, err := i.publicIdentityConfigSafeForHost(candidate, block)
		if err != nil {
			return err
		}
		if !safe {
			return nil
		}
	}
	i.report.UsesSafePublicIdentityConfig = true
	return nil
}

func (i *sshConfigInspector) publicIdentityConfigSafeForHost(host string, current sshConfigBlock) (bool, error) {
	identityAgentSet := false
	identityAgentIsPublic := false
	identitiesOnlySet := false
	identitiesOnlyIsYes := false

	apply := func(block sshConfigBlock) error {
		matches := block.kind == sshConfigBlockGlobal || block.kind == sshConfigBlockMatch
		if block.kind == sshConfigBlockHost {
			var err error
			matches, err = hostBlockMatches(block, host)
			if err != nil {
				return err
			}
		}
		if !matches {
			return nil
		}
		if !identityAgentSet && block.identityAgentSet {
			identityAgentSet = true
			identityAgentIsPublic = block.identityAgentIsPublic
		}
		if !identitiesOnlySet && block.identitiesOnlySet {
			identitiesOnlySet = true
			identitiesOnlyIsYes = block.identitiesOnlyIsYes
		}
		return nil
	}

	for _, block := range i.blocks {
		if err := apply(block); err != nil {
			return false, err
		}
	}
	if err := apply(current); err != nil {
		return false, err
	}
	return identityAgentSet && identityAgentIsPublic && identitiesOnlySet && identitiesOnlyIsYes, nil
}

func validateHostPatterns(patterns []string) error {
	for _, hostPattern := range patterns {
		_, pattern := splitHostPattern(hostPattern)
		if pattern == "" {
			return errors.New("empty Host pattern")
		}
		if _, err := path.Match(strings.ToLower(pattern), ""); err != nil {
			return fmt.Errorf("invalid Host pattern %q: %w", hostPattern, err)
		}
	}
	return nil
}

func literalHostCandidates(block sshConfigBlock) []string {
	seen := make(map[string]bool)
	var candidates []string
	for _, hostPattern := range block.hostPatterns {
		negated, pattern := splitHostPattern(hostPattern)
		if negated {
			continue
		}
		candidate, ok := literalHostPattern(pattern)
		if !ok {
			continue
		}
		candidate = strings.ToLower(candidate)
		matches, err := hostBlockMatches(block, candidate)
		if err != nil || !matches || seen[candidate] {
			continue
		}
		seen[candidate] = true
		candidates = append(candidates, candidate)
	}
	return candidates
}

func hostBlockMatches(block sshConfigBlock, host string) (bool, error) {
	positiveMatch := false
	host = strings.ToLower(host)
	for _, hostPattern := range block.hostPatterns {
		negated, pattern := splitHostPattern(hostPattern)
		matches, err := path.Match(strings.ToLower(pattern), host)
		if err != nil {
			return false, err
		}
		if negated && matches {
			return false, nil
		}
		if !negated && matches {
			positiveMatch = true
		}
	}
	return positiveMatch, nil
}

func splitHostPattern(pattern string) (bool, string) {
	if strings.HasPrefix(pattern, "!") {
		return true, strings.TrimPrefix(pattern, "!")
	}
	return false, pattern
}

func literalHostPattern(pattern string) (string, bool) {
	var literal strings.Builder
	escaped := false
	for index := 0; index < len(pattern); index++ {
		character := pattern[index]
		switch {
		case escaped:
			literal.WriteByte(character)
			escaped = false
		case character == '\\':
			escaped = true
		case character == '*' || character == '?' || character == '[':
			return "", false
		default:
			literal.WriteByte(character)
		}
	}
	return literal.String(), !escaped && literal.Len() > 0
}

func globWithErrors(pattern string) ([]string, error) {
	cleaned := filepath.Clean(pattern)
	volume := filepath.VolumeName(cleaned)
	remainder := strings.TrimPrefix(cleaned, volume)
	if !filepath.IsAbs(cleaned) {
		return nil, fmt.Errorf("pattern is not absolute: %s", pattern)
	}
	remainder = strings.TrimPrefix(remainder, string(filepath.Separator))
	if remainder == "" {
		return []string{volume + string(filepath.Separator)}, nil
	}

	paths := []string{volume + string(filepath.Separator)}
	components := strings.Split(remainder, string(filepath.Separator))
	for index, component := range components {
		if strings.ContainsAny(component, "*?[\\") {
			if _, err := filepath.Match(component, ""); err != nil {
				return nil, err
			}
			var matches []string
			for _, directory := range paths {
				entries, err := os.ReadDir(directory)
				if err != nil {
					return nil, err
				}
				for _, entry := range entries {
					matched, err := filepath.Match(component, entry.Name())
					if err != nil {
						return nil, err
					}
					if !matched {
						continue
					}
					candidate := filepath.Join(directory, entry.Name())
					if index < len(components)-1 {
						info, err := os.Stat(candidate)
						if err != nil {
							return nil, err
						}
						if !info.IsDir() {
							continue
						}
					}
					matches = append(matches, candidate)
				}
			}
			paths = matches
			continue
		}

		var matches []string
		for _, base := range paths {
			candidate := filepath.Join(base, component)
			info, err := os.Stat(candidate)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if index < len(components)-1 && !info.IsDir() {
				continue
			}
			matches = append(matches, candidate)
		}
		paths = matches
	}
	return paths, nil
}

func splitSSHDirective(line string) (string, string, bool) {
	separator := strings.IndexAny(line, " \t=")
	if separator < 0 {
		return "", "", false
	}
	directive := strings.ToLower(strings.TrimSpace(line[:separator]))
	remainder := strings.TrimSpace(line[separator:])
	if strings.HasPrefix(remainder, "=") {
		remainder = strings.TrimSpace(strings.TrimPrefix(remainder, "="))
	}
	if directive == "" {
		return "", "", false
	}
	return directive, remainder, true
}

func sshArguments(value string) ([]string, error) {
	var arguments []string
	var argument strings.Builder
	inQuote := false
	escaped := false
	hasArgument := false
	flush := func() {
		if hasArgument {
			arguments = append(arguments, argument.String())
			argument.Reset()
			hasArgument = false
		}
	}

	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case escaped:
			argument.WriteByte(character)
			hasArgument = true
			escaped = false
		case character == '\\':
			escaped = true
			hasArgument = true
		case character == '"':
			inQuote = !inQuote
			hasArgument = true
		case !inQuote && character == '#':
			flush()
			return arguments, nil
		case !inQuote && (character == ' ' || character == '\t'):
			flush()
		default:
			argument.WriteByte(character)
			hasArgument = true
		}
	}
	if escaped {
		return nil, errors.New("unfinished escape")
	}
	if inQuote {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return arguments, nil
}

func sshPathsEqual(configured string, target string, home string) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	return normalizeSSHPath(configured, home) == normalizeSSHPath(target, home)
}

func normalizeSSHPath(value string, home string) string {
	value = strings.ReplaceAll(value, "%d", home)
	if value == "~" {
		return home
	}
	if strings.HasPrefix(value, "~/") {
		return filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	return filepath.Clean(value)
}
