package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/winky/envguard/internal/advice"
	"github.com/winky/envguard/internal/reporter"
	"github.com/winky/envguard/internal/scanner"
)

const version = "0.1.0"

// StringSliceFlag implements flag.Value for repeated string flags.
type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// validScanners lists the valid scanner names.
var validScanners = map[string]bool{
	"env":       true,
	"shell":     true,
	"files":     true,
	"launchctl": true,
	"agents":    true,
	"direnv":    true,
}

// validRisks maps risk level names to Risk values.
var validRisks = map[string]scanner.Risk{
	"critical": scanner.RiskCritical,
	"high":     scanner.RiskHigh,
	"medium":   scanner.RiskMedium,
	"low":      scanner.RiskLow,
	"info":     scanner.RiskInfo,
}

// riskWeight returns the numeric weight of a risk level for comparison.
func riskWeight(r scanner.Risk) int {
	switch r {
	case scanner.RiskCritical:
		return 5
	case scanner.RiskHigh:
		return 4
	case scanner.RiskMedium:
		return 3
	case scanner.RiskLow:
		return 2
	case scanner.RiskInfo:
		return 1
	default:
		return 0
	}
}

// Run is the main entry point for the CLI.
func Run() int {
	var (
		jsonFlag    bool
		summaryFlag bool
		noColor     bool
		skip        StringSliceFlag
		only        StringSliceFlag
		depth       int
		minRisk     string
		quiet       bool
		versionFlag bool
	)

	flag.BoolVar(&jsonFlag, "json", false, "JSON 形式で出力")
	flag.BoolVar(&summaryFlag, "summary", false, "件数のみ表示")
	flag.BoolVar(&noColor, "no-color", false, "ANSI カラー無効化")
	flag.Var(&skip, "skip", "特定スキャナをスキップ（複数指定可）")
	flag.Var(&only, "only", "指定スキャナのみ実行（--skip と排他）")
	flag.IntVar(&depth, "depth", 4, ".envrc 走査の最大階層")
	flag.StringVar(&minRisk, "min-risk", "", "指定レベル以上のみ表示")
	flag.BoolVar(&quiet, "quiet", false, "進捗ログを抑止")
	flag.BoolVar(&versionFlag, "version", false, "バージョン表示")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: envguard [OPTIONS]\n\nOPTIONS:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if versionFlag {
		fmt.Printf("envguard %s\n", version)
		return 0
	}

	// Validate --skip and --only are not both specified
	if len(skip) > 0 && len(only) > 0 {
		fmt.Fprintln(os.Stderr, "エラー: --skip と --only は同時に指定できません")
		return 2
	}

	// Validate scanner names
	for _, s := range skip {
		if !validScanners[s] {
			fmt.Fprintf(os.Stderr, "エラー: 不明なスキャナ: %s\n", s)
			return 2
		}
	}
	for _, s := range only {
		if !validScanners[s] {
			fmt.Fprintf(os.Stderr, "エラー: 不明なスキャナ: %s\n", s)
			return 2
		}
	}

	// Validate --min-risk
	var minRiskLevel scanner.Risk
	if minRisk != "" {
		r, ok := validRisks[strings.ToLower(minRisk)]
		if !ok {
			fmt.Fprintf(os.Stderr, "エラー: 不明なリスクレベル: %s\n", minRisk)
			return 2
		}
		minRiskLevel = r
	}

	// Determine which scanners to run
	skipSet := make(map[string]bool)
	for _, s := range skip {
		skipSet[s] = true
	}
	onlySet := make(map[string]bool)
	for _, s := range only {
		onlySet[s] = true
	}

	shouldRun := func(name string) bool {
		if len(onlySet) > 0 {
			return onlySet[name]
		}
		return !skipSet[name]
	}

	// Build scanner list
	type namedScanner struct {
		name    string
		scanner scanner.Scanner
	}

	var scanners []namedScanner
	if shouldRun("env") {
		scanners = append(scanners, namedScanner{"env", &scanner.EnvScanner{}})
	}
	if shouldRun("shell") {
		scanners = append(scanners, namedScanner{"shell", &scanner.ShellConfigScanner{}})
	}
	if shouldRun("files") {
		scanners = append(scanners, namedScanner{"files", &scanner.CredFilesScanner{}})
	}
	if shouldRun("launchctl") {
		scanners = append(scanners, namedScanner{"launchctl", &scanner.LaunchctlScanner{}})
	}
	// TODO: Enable when scanner implementations are available
	// if shouldRun("agents") {
	// 	scanners = append(scanners, namedScanner{"agents", &scanner.LaunchAgentsScanner{}})
	// }
	// if shouldRun("direnv") {
	// 	scanners = append(scanners, namedScanner{"direnv", &scanner.DirenvScanner{Depth: depth}})
	// }

	// Run scanners and collect findings
	var allFindings []scanner.Finding
	for _, ns := range scanners {
		if !quiet {
			fmt.Fprintf(os.Stderr, "[scanning] %s...\n", ns.name)
		}
		findings, err := ns.scanner.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] %s: %v\n", ns.name, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Filter by --min-risk
	if minRiskLevel != "" {
		minWeight := riskWeight(minRiskLevel)
		var filtered []scanner.Finding
		for _, f := range allFindings {
			if riskWeight(f.Risk) >= minWeight {
				filtered = append(filtered, f)
			}
		}
		allFindings = filtered
	}

	// Generate advice and warnings
	advices := advice.Generate(allFindings)
	warnings := []string{
		".envrc の動的構文（コマンド置換等）は検出対象外です",
	}

	// Output
	if jsonFlag {
		if err := reporter.RenderJSON(os.Stdout, allFindings, advices, warnings); err != nil {
			fmt.Fprintf(os.Stderr, "エラー: JSON 出力に失敗: %v\n", err)
			return 2
		}
	} else if summaryFlag {
		counts := make(map[scanner.Risk]int)
		for _, f := range allFindings {
			counts[f.Risk]++
		}
		fmt.Printf("CRITICAL %d / HIGH %d / MEDIUM %d / LOW %d / INFO %d\n",
			counts[scanner.RiskCritical],
			counts[scanner.RiskHigh],
			counts[scanner.RiskMedium],
			counts[scanner.RiskLow],
			counts[scanner.RiskInfo],
		)
	} else {
		if err := reporter.RenderText(os.Stdout, allFindings, noColor); err != nil {
			fmt.Fprintf(os.Stderr, "エラー: レポート出力に失敗: %v\n", err)
			return 2
		}
	}

	// Exit code: 1 if any findings, 0 if none
	if len(allFindings) > 0 {
		return 1
	}
	return 0
}
