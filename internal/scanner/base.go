// Package scanner provides the Scanner interface and re-exports core model types
// for use within the scanner sub-packages.
package scanner

import "github.com/winky/envguard/internal/model"

// Re-export model types so scanner implementations can use a single import.
type (
	Risk    = model.Risk
	Source  = model.Source
	Finding = model.Finding
	Scanner = model.Scanner
)

const (
	RiskCritical = model.RiskCritical
	RiskHigh     = model.RiskHigh
	RiskMedium   = model.RiskMedium
	RiskLow      = model.RiskLow
	RiskInfo     = model.RiskInfo

	SourceEnv            = model.SourceEnv
	SourceShellConfig    = model.SourceShellConfig
	SourceCredentialFile = model.SourceCredentialFile
	SourceLaunchctl      = model.SourceLaunchctl
	SourceLaunchAgent    = model.SourceLaunchAgent
	SourceDirenv         = model.SourceDirenv
)
