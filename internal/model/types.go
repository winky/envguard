package model

// Risk represents the severity level of a finding.
type Risk string

const (
	RiskCritical Risk = "critical"
	RiskHigh     Risk = "high"
	RiskMedium   Risk = "medium"
	RiskLow      Risk = "low"
	RiskInfo     Risk = "info"
)

// Source represents where a finding was detected.
type Source string

const (
	SourceEnv            Source = "env"
	SourceShellConfig    Source = "shell_config"
	SourceCredentialFile Source = "credential_file"
	SourceLaunchctl      Source = "launchctl"
	SourceLaunchAgent    Source = "launch_agent"
	SourceDirenv         Source = "direnv"
)

// Finding represents a single detected credential or sensitive configuration.
type Finding struct {
	Source      Source  `json:"source"`
	Key         string  `json:"key"`
	MaskedValue *string `json:"masked_value"`
	Location    string  `json:"location"`
	Risk        Risk    `json:"risk"`
	Note        *string `json:"note,omitempty"`
}

// Scanner is the interface that all credential scanners implement.
type Scanner interface {
	Scan() ([]Finding, error)
}
