package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanShellFile(t *testing.T) {
	// Copy sample.zshrc to a temp directory
	tmpDir := t.TempDir()
	src, err := os.ReadFile("../../testdata/sample.zshrc")
	if err != nil {
		t.Fatalf("failed to read sample.zshrc: %v", err)
	}
	tmpFile := filepath.Join(tmpDir, ".zshrc")
	if err := os.WriteFile(tmpFile, src, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	findings, err := scanShellFile(tmpFile, "~/.zshrc")
	if err != nil {
		t.Fatalf("scanShellFile returned error: %v", err)
	}

	// Count by risk level
	riskCounts := make(map[string]int)
	for _, f := range findings {
		riskCounts[string(f.Risk)]++
	}

	if riskCounts["critical"] != 1 {
		t.Errorf("expected 1 CRITICAL finding (AWS_SECRET_ACCESS_KEY), got %d", riskCounts["critical"])
	}
	if riskCounts["high"] != 3 {
		t.Errorf("expected 3 HIGH findings (GITHUB_TOKEN, OPENAI_API_KEY, VAULT_TOKEN), got %d", riskCounts["high"])
	}
	if riskCounts["low"] != 1 {
		t.Errorf("expected 1 LOW finding, got %d", riskCounts["low"])
	}

	// Check OPENAI_API_KEY has a note (no export)
	for _, f := range findings {
		if f.Key == "OPENAI_API_KEY" {
			if f.Note == nil {
				t.Error("OPENAI_API_KEY should have a note about missing export")
			}
			break
		}
	}

	// Check NORMAL_VAR is not detected
	for _, f := range findings {
		if f.Key == "NORMAL_VAR" {
			t.Error("NORMAL_VAR should not be detected")
		}
	}
}
