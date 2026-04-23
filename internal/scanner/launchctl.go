//go:build darwin

package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/winky/envguard/internal/masking"
	"github.com/winky/envguard/internal/patterns"
)

// LaunchctlScanner probes macOS launchctl for environment variables.
type LaunchctlScanner struct{}

func (s *LaunchctlScanner) Scan() ([]Finding, error) {
	var findings []Finding

	for _, varName := range patterns.LaunchctlCandidates {
		cmd := exec.Command("launchctl", "getenv", varName)
		out, err := cmd.Output()
		if err != nil {
			var execErr *exec.Error
			if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
				fmt.Fprintln(os.Stderr, "[WARN] launchctl: コマンドが見つかりません")
				return nil, nil
			}
			// Non-zero exit means the variable is not set; skip.
			continue
		}

		value := strings.TrimSpace(string(out))
		if value == "" {
			continue
		}

		risk, ok := patterns.Classify(varName)
		if !ok {
			continue
		}

		masked := masking.Mask(value)
		findings = append(findings, Finding{
			Source:      SourceLaunchctl,
			Key:         varName,
			MaskedValue: &masked,
			Location:    "launchctl setenv",
			Risk:        risk,
		})
	}

	return findings, nil
}
