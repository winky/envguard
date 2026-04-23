package patterns

import (
	"testing"

	"github.com/winky/envguard/internal/model"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		wantRisk model.Risk
		wantOK   bool
	}{
		{"AWS_SECRET_ACCESS_KEY is critical", "AWS_SECRET_ACCESS_KEY", model.RiskCritical, true},
		{"GITHUB_TOKEN is high", "GITHUB_TOKEN", model.RiskHigh, true},
		{"AWS_ACCESS_KEY_ID is medium", "AWS_ACCESS_KEY_ID", model.RiskMedium, true},
		{"AWS_REGION is low", "AWS_REGION", model.RiskLow, true},
		{"NORMAL_VAR no match", "NORMAL_VAR", "", false},
		{"TF_VAR_DB_PASSWORD overrides to critical", "TF_VAR_DB_PASSWORD", model.RiskCritical, true},
		{"TF_VAR_API_KEY overrides to high", "TF_VAR_API_KEY", model.RiskHigh, true},
		{"TF_VAR_REGION stays medium", "TF_VAR_REGION", model.RiskMedium, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRisk, gotOK := Classify(tt.key)
			if gotOK != tt.wantOK {
				t.Errorf("Classify(%q) ok = %v, want %v", tt.key, gotOK, tt.wantOK)
				return
			}
			if gotRisk != tt.wantRisk {
				t.Errorf("Classify(%q) risk = %q, want %q", tt.key, gotRisk, tt.wantRisk)
			}
		})
	}
}
