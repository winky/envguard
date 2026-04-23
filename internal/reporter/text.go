package reporter

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/winky/envguard/internal/scanner"
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
)

// riskOrder defines the display order of risk levels.
var riskOrder = []scanner.Risk{
	scanner.RiskCritical,
	scanner.RiskHigh,
	scanner.RiskMedium,
	scanner.RiskLow,
	scanner.RiskInfo,
}

func riskColor(r scanner.Risk) string {
	switch r {
	case scanner.RiskCritical:
		return colorRed
	case scanner.RiskHigh:
		return colorMagenta
	case scanner.RiskMedium:
		return colorYellow
	case scanner.RiskLow:
		return colorCyan
	case scanner.RiskInfo:
		return colorWhite
	default:
		return colorWhite
	}
}

func riskPrefix(r scanner.Risk) string {
	switch r {
	case scanner.RiskCritical, scanner.RiskHigh:
		return "x"
	case scanner.RiskMedium, scanner.RiskLow:
		return "!"
	default:
		return "."
	}
}

// isTerminal checks if stdout is a terminal.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// shouldUseColor determines whether to use ANSI color codes.
func shouldUseColor(noColor bool) bool {
	if noColor {
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	return isTerminal()
}

// groupByRisk groups findings by risk level.
func groupByRisk(findings []scanner.Finding) map[scanner.Risk][]scanner.Finding {
	grouped := make(map[scanner.Risk][]scanner.Finding)
	for _, f := range findings {
		grouped[f.Risk] = append(grouped[f.Risk], f)
	}
	return grouped
}

// RenderText writes a text-format report to the given writer.
func RenderText(w io.Writer, findings []scanner.Finding, noColor bool) error {
	useColor := shouldUseColor(noColor)

	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05 MST")

	// Header
	fmt.Fprintln(w, "================================================================")
	fmt.Fprintln(w, "  envguard レポート")
	fmt.Fprintf(w, "  実行日時: %s\n", now)
	fmt.Fprintf(w, "  ホスト: %s\n", hostname)
	fmt.Fprintln(w, "================================================================")
	fmt.Fprintln(w)

	grouped := groupByRisk(findings)

	// Sort findings within each group by key
	for _, fs := range grouped {
		sort.Slice(fs, func(i, j int) bool {
			return fs[i].Key < fs[j].Key
		})
	}

	// Summary counts
	counts := make(map[scanner.Risk]int)
	for _, r := range riskOrder {
		counts[r] = len(grouped[r])
	}

	// Render each risk level section
	for _, risk := range riskOrder {
		fs, ok := grouped[risk]
		if !ok || len(fs) == 0 {
			continue
		}

		label := fmt.Sprintf("[%s] %d 件", strings.ToUpper(string(risk)), len(fs))
		if useColor {
			fmt.Fprintf(w, "%s%s%s\n", riskColor(risk), label, colorReset)
		} else {
			fmt.Fprintln(w, label)
		}

		prefix := riskPrefix(risk)
		for _, f := range fs {
			if risk == scanner.RiskInfo {
				// INFO findings (e.g. credential files) show note instead of key/value
				note := ""
				if f.Note != nil {
					note = *f.Note
				}
				if f.MaskedValue != nil {
					fmt.Fprintf(w, "  %s %s\n", prefix, f.Key)
					fmt.Fprintf(w, "      場所: %s\n", f.Location)
					fmt.Fprintf(w, "      値:   %s\n", *f.MaskedValue)
				} else {
					fmt.Fprintf(w, "  %s %s (%s)\n", prefix, f.Location, note)
				}
			} else {
				fmt.Fprintf(w, "  %s %s\n", prefix, f.Key)
				fmt.Fprintf(w, "      場所: %s\n", f.Location)
				if f.MaskedValue != nil {
					fmt.Fprintf(w, "      値:   %s\n", *f.MaskedValue)
				}
			}
		}
		fmt.Fprintln(w)
	}

	// Summary line
	fmt.Fprintln(w, "----------------------------------------------------------------")
	fmt.Fprintf(w, "サマリ: CRITICAL %d / HIGH %d / MEDIUM %d / LOW %d / INFO %d\n",
		counts[scanner.RiskCritical],
		counts[scanner.RiskHigh],
		counts[scanner.RiskMedium],
		counts[scanner.RiskLow],
		counts[scanner.RiskInfo],
	)
	fmt.Fprintln(w, "----------------------------------------------------------------")

	return nil
}
