package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/RodKast/Vex/pkg/types"
)

const (
	colorRed    = "\033[31m"
	colorOrange = "\033[33m"
	colorYellow = "\033[93m"
	colorBlue   = "\033[34m"
	colorReset  = "\033[0m"
)

func severityIcon(severity string) string {
	switch severity {
	case "critical":
		return colorRed + "!" + colorReset
	case "high":
		return colorOrange + "!" + colorReset
	case "medium":
		return colorYellow + "!" + colorReset
	case "info":
		return colorBlue + "!" + colorReset
	default:
		return ""
	}
}

func PrintFindings(findings []types.Finding) {
	if len(findings) == 0 {
		return
	}

	seen := map[string]bool{}
	var deduped []types.Finding
	for _, f := range findings {
		key := f.Title + f.URL + f.Parameter
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, f)
	}

	// Sort by severity: critical > high > medium > low
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(deduped, func(i, j int) bool {
		return order[deduped[i].Severity] < order[deduped[j].Severity]
	})

	fmt.Printf("\n%-12s %-35s %-15s %s\n", "SEVERITY", "TITLE", "PARAMETER", "URL")
	fmt.Printf("%-12s %-35s %-15s %s\n",
		strings.Repeat("─", 10),
		strings.Repeat("─", 33),
		strings.Repeat("─", 13),
		strings.Repeat("─", 30),
	)

	for _, f := range deduped {
		severity := severityColor(f.Severity) + fmt.Sprintf("%-10s", f.Severity) + colorReset
		param := f.Parameter
		if param == "" {
			param = "-"
		}
		fmt.Printf("%-22s %-35s %-15s %s\n", severity, truncate(f.Title, 33), truncate(param, 13), f.URL)
	}
	fmt.Println()
}

func severityColor(severity string) string {
	switch severity {
	case "critical":
		return colorRed
	case "high":
		return colorOrange
	case "medium":
		return colorYellow
	case "info":
		return colorBlue
	default:
		return ""
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-2] + ".."
}

func PrintJSON(findings []types.Finding) {
	b, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Println("[]")
		return
	}
	fmt.Println(string(b))
}
