package scanner

import (
	"os"
	"strings"

	"github.com/winky/envguard/internal/masking"
	"github.com/winky/envguard/internal/patterns"
)

// EnvScanner scans the current process environment variables.
type EnvScanner struct{}

// Scan iterates over os.Environ() and returns findings for any keys
// that match known credential patterns.
func (s *EnvScanner) Scan() ([]Finding, error) {
	var findings []Finding

	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]

		risk, matched := patterns.Classify(key)
		if !matched {
			continue
		}

		masked := masking.Mask(value)
		findings = append(findings, Finding{
			Source:      SourceEnv,
			Key:        key,
			MaskedValue: &masked,
			Location:   "環境変数（現在のシェル）",
			Risk:       risk,
		})
	}

	return findings, nil
}
