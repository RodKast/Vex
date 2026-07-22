package output

import (
	"fmt"

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
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Title + f.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		icon := severityIcon(f.Severity)
		fmt.Printf("%s [%s] %s - %s\n", icon, f.Severity, f.Title, f.URL)
		if f.Parameter != "" {
			fmt.Printf("   Parameter: %s\n", f.Parameter)
		}
		fmt.Printf("   Description: %s\n", f.Description)
		fmt.Printf("   Evidence: %s\n", f.Evidence)
		fmt.Println()
	}
}
