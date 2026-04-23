//go:build darwin

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanPlist(t *testing.T) {
	// Copy sample_agent.plist to a temp directory
	tmpDir := t.TempDir()
	src, err := os.ReadFile("../../testdata/sample_agent.plist")
	if err != nil {
		t.Fatalf("failed to read sample_agent.plist: %v", err)
	}
	tmpFile := filepath.Join(tmpDir, "com.example.agent.plist")
	if err := os.WriteFile(tmpFile, src, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	findings, err := scanPlist(tmpFile)
	if err != nil {
		t.Fatalf("scanPlist returned error: %v", err)
	}

	// AWS_ACCESS_KEY_ID should be detected
	found := false
	for _, f := range findings {
		if f.Key == "AWS_ACCESS_KEY_ID" {
			found = true
			break
		}
	}
	if !found {
		t.Error("AWS_ACCESS_KEY_ID should be detected")
	}

	// NORMAL_VAR should not be detected
	for _, f := range findings {
		if f.Key == "NORMAL_VAR" {
			t.Error("NORMAL_VAR should not be detected")
		}
	}
}
