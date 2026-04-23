package advice

import "github.com/winky/envguard/internal/model"

// Advice represents a remediation suggestion for detected findings.
type Advice struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Command string `json:"command"`
}

// Generate returns remediation advice based on the sources present in findings.
func Generate(findings []model.Finding) []Advice {
	sources := make(map[model.Source]bool)
	for _, f := range findings {
		sources[f.Source] = true
	}

	var advice []Advice

	if sources[model.SourceEnv] || sources[model.SourceShellConfig] || sources[model.SourceDirenv] {
		advice = append(advice, Advice{
			ID:      "env-isolation",
			Title:   "環境変数の分離起動",
			Command: "env -i HOME=\"$HOME\" PATH=\"$PATH\" bash --norc --noprofile",
		})
	}

	if sources[model.SourceCredentialFile] {
		advice = append(advice, Advice{
			ID:      "credential-manager",
			Title:   "クレデンシャルマネージャの利用",
			Command: "aws-vault exec <profile> -- <command>  # または 1Password CLI: op run -- <command>",
		})
	}

	if sources[model.SourceLaunchAgent] {
		advice = append(advice, Advice{
			ID:      "launch-agent-review",
			Title:   "LaunchAgent の確認",
			Command: "ls ~/Library/LaunchAgents/ && plutil -p ~/Library/LaunchAgents/*.plist",
		})
	}

	return advice
}
