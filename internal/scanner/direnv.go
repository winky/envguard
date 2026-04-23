package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/winky/envguard/internal/masking"
	"github.com/winky/envguard/internal/patterns"
)

// excludeDirs is the set of directory names to skip during direnv scanning.
var excludeDirs = map[string]bool{
	"node_modules":  true,
	".git":          true,
	"Library":       true,
	"Applications":  true,
	"Movies":        true,
	"Music":         true,
	"Pictures":      true,
	"Downloads":     true,
	".Trash":        true,
}

// DirenvScanner scans for .envrc files under $HOME.
type DirenvScanner struct {
	Depth int // maximum directory depth (default 4)
}

func (s *DirenvScanner) Scan() ([]Finding, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	maxDepth := s.Depth
	if maxDepth <= 0 {
		maxDepth = 4
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	homeDepth := strings.Count(home, string(filepath.Separator))

	var findings []Finding
	timedOut := false

	_ = filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}

		// Check timeout.
		select {
		case <-ctx.Done():
			timedOut = true
			return filepath.SkipAll
		default:
		}

		if d.IsDir() {
			// Check depth.
			depth := strings.Count(path, string(filepath.Separator)) - homeDepth
			if depth > maxDepth {
				return filepath.SkipDir
			}
			// Check exclusions.
			if excludeDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Name() != ".envrc" {
			return nil
		}

		ff, scanErr := scanEnvrc(path)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "[WARN] direnv: %s: %s\n", path, scanErr.Error())
			return nil
		}
		findings = append(findings, ff...)
		return nil
	})

	if timedOut {
		fmt.Fprintln(os.Stderr, "[WARN] direnv: スキャンタイムアウト（部分結果）")
	}

	return findings, nil
}

// scanEnvrc scans a single .envrc file for environment variable assignments.
func scanEnvrc(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		var key, value string
		if m := reExport.FindStringSubmatch(line); m != nil {
			key = m[1]
			value = unquote(m[2])
		} else if m := reSetenv.FindStringSubmatch(line); m != nil {
			key = m[1]
			value = unquote(m[2])
		} else if m := reBare.FindStringSubmatch(line); m != nil {
			key = m[1]
			value = unquote(m[2])
		} else {
			continue
		}

		risk, ok := patterns.Classify(key)
		if !ok {
			continue
		}

		masked := masking.Mask(value)
		location := fmt.Sprintf("%s:%d", path, lineNo)
		findings = append(findings, Finding{
			Source:      SourceDirenv,
			Key:         key,
			MaskedValue: &masked,
			Location:    location,
			Risk:        risk,
		})
	}
	return findings, sc.Err()
}
