//go:build !darwin

package scanner

// LaunchctlScanner is a no-op stub for non-macOS platforms.
type LaunchctlScanner struct{}

func (s *LaunchctlScanner) Scan() ([]Finding, error) {
	return nil, nil // macOS 以外では自動スキップ
}
