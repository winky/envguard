//go:build darwin

package scanner

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"

	"github.com/winky/envguard/internal/patterns"
)

// LaunchAgentsScanner scans ~/Library/LaunchAgents plist files for environment variables.
type LaunchAgentsScanner struct{}

func (s *LaunchAgentsScanner) Scan() ([]Finding, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	globPattern := filepath.Join(home, "Library", "LaunchAgents", "*.plist")
	matches, err := filepath.Glob(globPattern)
	if err != nil {
		return nil, fmt.Errorf("glob error: %w", err)
	}

	var findings []Finding
	for _, path := range matches {
		ff, err := scanPlist(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] launchagents: %s: %s\n", path, err.Error())
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

// plist represents the top-level <plist> element.
type plist struct {
	Dict plistDict `xml:"dict"`
}

// plistDict represents a <dict> element containing interleaved <key> and value elements.
type plistDict struct {
	Inner []byte `xml:",innerxml"`
}

// scanPlist parses a plist file and extracts environment variable keys.
func scanPlist(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	keys, err := extractEnvKeys(data)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, key := range keys {
		risk, ok := patterns.Classify(key)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			Source:      SourceLaunchAgent,
			Key:         key,
			MaskedValue: nil,
			Location:    path,
			Risk:        risk,
		})
	}
	return findings, nil
}

// extractEnvKeys walks the XML tokens to find <key>EnvironmentVariables</key>
// followed by a <dict> block, then extracts all <key> elements from that dict.
func extractEnvKeys(data []byte) ([]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose

	var keys []string
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}

		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "key" {
			continue
		}

		// Read the key's text content.
		charTok, err := decoder.Token()
		if err != nil {
			break
		}
		charData, ok := charTok.(xml.CharData)
		if !ok || string(charData) != "EnvironmentVariables" {
			continue
		}

		// Skip past </key> and find the next <dict>.
		if err := skipToEndElement(decoder, "key"); err != nil {
			break
		}

		keys, err = readDictKeys(decoder)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EnvironmentVariables dict: %w", err)
		}
		break
	}
	return keys, nil
}

// skipToEndElement consumes tokens until it finds the end element with the given name.
func skipToEndElement(decoder *xml.Decoder, name string) error {
	for {
		tok, err := decoder.Token()
		if err != nil {
			return err
		}
		if ee, ok := tok.(xml.EndElement); ok && ee.Name.Local == name {
			return nil
		}
	}
}

// readDictKeys finds the next <dict> and reads all <key> elements within it.
func readDictKeys(decoder *xml.Decoder) ([]string, error) {
	// Find the opening <dict>.
	for {
		tok, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "dict" {
			break
		}
	}

	// Read keys until </dict>.
	var keys []string
	depth := 1
	for depth > 0 {
		tok, err := decoder.Token()
		if err != nil {
			return keys, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "dict" {
				depth++
			} else if t.Name.Local == "key" && depth == 1 {
				charTok, err := decoder.Token()
				if err != nil {
					return keys, err
				}
				if cd, ok := charTok.(xml.CharData); ok {
					keys = append(keys, string(cd))
				}
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				depth--
			}
		}
	}
	return keys, nil
}

