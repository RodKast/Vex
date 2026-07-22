package output

import (
	"fmt"

	"github.com/RodKast/Vex/pkg/types"
)

func PrintSummary(findings []types.Finding) {
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Title + f.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		counts[f.Severity]++
	}
	fmt.Println("\n=== Scan Summary ===")
	severities := []string{"critical", "high", "medium", "info"}
	for _, s := range severities {
		if counts[s] > 0 {
			fmt.Printf("%s [%s]: %d\n", severityIcon(s), s, counts[s])
		}
	}
}
