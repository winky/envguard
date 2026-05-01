package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/winky/envguard/internal/scanner"
)

type hookOutput struct {
	SystemMessage string `json:"systemMessage,omitempty"`
}

// RenderHook writes a Claude Code hook-compatible JSON to w.
// Outputs nothing if findings is empty.
func RenderHook(w io.Writer, findings []scanner.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	counts := make(map[scanner.Risk]int)
	for _, f := range findings {
		counts[f.Risk]++
	}

	var parts []string
	for _, risk := range []scanner.Risk{scanner.RiskCritical, scanner.RiskHigh, scanner.RiskMedium, scanner.RiskLow} {
		if n := counts[risk]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d件", strings.ToUpper(string(risk)), n))
		}
	}

	msg := fmt.Sprintf(
		"[envguard] 環境内に認証情報が検出されました: %s\nこれらが Claude に公開される可能性があります。詳細は `envguard` を実行してください。",
		strings.Join(parts, " / "),
	)

	return json.NewEncoder(w).Encode(hookOutput{SystemMessage: msg})
}
