package reporter

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/winky/envguard/internal/advice"
	"github.com/winky/envguard/internal/scanner"
)

// Report is the top-level JSON output structure.
type Report struct {
	SchemaVersion string         `json:"schema_version"`
	GeneratedAt   string         `json:"generated_at"`
	Host          string         `json:"host"`
	Summary       map[string]int `json:"summary"`
	Findings      []finding      `json:"findings"`
	Advice        []advice.Advice `json:"advice"`
	Warnings      []string       `json:"warnings"`
}

// finding is a JSON-serializable version of scanner.Finding.
type finding struct {
	Source      string  `json:"source"`
	Key        string  `json:"key"`
	MaskedValue *string `json:"masked_value"`
	Location   string  `json:"location"`
	Risk       string  `json:"risk"`
	Note       *string `json:"note,omitempty"`
}

// RenderJSON writes a JSON-format report to the given writer.
func RenderJSON(w io.Writer, findings []scanner.Finding, advices []advice.Advice, warnings []string) error {
	hostname, _ := os.Hostname()

	summary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range findings {
		summary[string(f.Risk)]++
	}

	jsonFindings := make([]finding, len(findings))
	for i, f := range findings {
		jsonFindings[i] = finding{
			Source:      string(f.Source),
			Key:        f.Key,
			MaskedValue: f.MaskedValue,
			Location:   f.Location,
			Risk:       string(f.Risk),
			Note:       f.Note,
		}
	}

	if advices == nil {
		advices = []advice.Advice{}
	}
	if warnings == nil {
		warnings = []string{}
	}

	report := Report{
		SchemaVersion: "1.1",
		GeneratedAt:   time.Now().Format(time.RFC3339),
		Host:          hostname,
		Summary:       summary,
		Findings:      jsonFindings,
		Advice:        advices,
		Warnings:      warnings,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
