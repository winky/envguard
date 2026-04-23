package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/winky/envguard/internal/advice"
	"github.com/winky/envguard/internal/scanner"
)

func TestRenderText(t *testing.T) {
	masked := "****cret"
	findings := []scanner.Finding{
		{
			Source:      scanner.SourceShellConfig,
			Key:         "AWS_SECRET_ACCESS_KEY",
			MaskedValue: &masked,
			Location:    "~/.zshrc:2",
			Risk:        scanner.RiskCritical,
		},
	}

	var buf bytes.Buffer
	if err := RenderText(&buf, findings, true); err != nil {
		t.Fatalf("RenderText returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CRITICAL") {
		t.Error("output should contain CRITICAL section")
	}
}

func TestRenderJSON(t *testing.T) {
	masked := "****cret"
	findings := []scanner.Finding{
		{
			Source:      scanner.SourceShellConfig,
			Key:         "AWS_SECRET_ACCESS_KEY",
			MaskedValue: &masked,
			Location:    "~/.zshrc:2",
			Risk:        scanner.RiskCritical,
		},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, findings, []advice.Advice{}, []string{}); err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}

	// Verify valid JSON
	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if report.SchemaVersion != "1.1" {
		t.Errorf("schema_version = %q, want %q", report.SchemaVersion, "1.1")
	}
}
