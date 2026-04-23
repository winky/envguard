package scanner

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/winky/envguard/internal/patterns"
)

type CredFilesScanner struct{}

func (s *CredFilesScanner) Scan() ([]Finding, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	var findings []Finding
	for _, cp := range patterns.CredentialPaths {
		expanded := expandTilde(cp.Path, home)
		info, err := os.Stat(expanded)
		if err != nil {
			continue
		}

		sizeKB := fmt.Sprintf("%.1fKB", float64(info.Size())/1024.0)
		if info.IsDir() {
			sizeKB = "dir"
		}
		updated := info.ModTime().Format(time.DateOnly)

		riskLabel := strings.ToUpper(string(cp.Risk))
		note := fmt.Sprintf("%s [%s], %s, 更新 %s", cp.Note, riskLabel, sizeKB, updated)

		findings = append(findings, Finding{
			Source:      SourceCredentialFile,
			Key:         cp.Note,
			MaskedValue: nil,
			Location:    expanded,
			Risk:        RiskInfo,
			Note:        &note,
		})
	}
	return findings, nil
}
