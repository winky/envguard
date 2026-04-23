//go:build !darwin

package scanner

// LaunchAgentsScanner is a no-op stub for non-macOS platforms.
type LaunchAgentsScanner struct{}

func (s *LaunchAgentsScanner) Scan() ([]Finding, error) {
	return nil, nil
}
