package scanner

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/winky/envguard/internal/masking"
	"github.com/winky/envguard/internal/patterns"
)

var shellConfigFiles = []string{
	"~/.zshrc", "~/.zshenv", "~/.zprofile",
	"~/.bashrc", "~/.bash_profile", "~/.profile",
	"/etc/zshenv", "/etc/zprofile", "/etc/profile",
}

var (
	reExport = regexp.MustCompile(`^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)`)
	reBare   = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)`)
	reSetenv = regexp.MustCompile(`^\s*setenv\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.*)`)
)

type ShellConfigScanner struct{}

func (s *ShellConfigScanner) Scan() ([]Finding, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	var findings []Finding
	for _, path := range shellConfigFiles {
		expanded := expandTilde(path, home)
		ff, err := scanShellFile(expanded, path)
		if err != nil {
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

func expandTilde(path, home string) string {
	if strings.HasPrefix(path, "~/") {
		return home + path[1:]
	}
	return path
}

func scanShellFile(absPath, displayPath string) ([]Finding, error) {
	f, err := os.Open(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "[WARN] shell: %s: %s\n", absPath, err.Error())
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		var key, value string
		var note *string

		if m := reExport.FindStringSubmatch(line); m != nil {
			key = m[1]
			value = unquote(m[2])
		} else if m := reSetenv.FindStringSubmatch(line); m != nil {
			key = m[1]
			value = unquote(m[2])
		} else if m := reBare.FindStringSubmatch(line); m != nil {
			key = m[1]
			value = unquote(m[2])
			n := "export なし（シェル関数内ローカル変数の可能性あり）"
			note = &n
		} else {
			continue
		}

		risk, ok := patterns.Classify(key)
		if !ok {
			continue
		}

		masked := masking.Mask(value)
		location := fmt.Sprintf("%s:%d", displayPath, lineNo)

		findings = append(findings, Finding{
			Source:      SourceShellConfig,
			Key:         key,
			MaskedValue: &masked,
			Location:    location,
			Risk:        risk,
			Note:        note,
		})
	}
	return findings, scanner.Err()
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
