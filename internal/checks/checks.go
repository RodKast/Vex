package checks

import (
	"context"

	"github.com/RodKast/Vex/pkg/types"
)

var registry []types.VulnCheck

func Register(c types.VulnCheck) {
	registry = append(registry, c)
}

var pageRegistry []types.PageCheck

func RegisterPage(c types.PageCheck) {
	pageRegistry = append(pageRegistry, c)
}

func RunAll(ctx context.Context, points []types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	var findings []types.Finding

	// Deduplicate URLs for page-level checks
	seen := make(map[string]bool)
	for _, point := range points {
		if seen[point.URL] {
			continue
		}
		seen[point.URL] = true
		for _, check := range pageRegistry {
			f := check.Run(ctx, point.URL, eng)
			findings = append(findings, f...)
		}
	}

	// Run injection checks once per parameter
	for _, point := range points {
		for _, check := range registry {
			f := check.Run(ctx, point, eng)
			findings = append(findings, f...)
		}
	}

	return findings
}

func RunAllPages(ctx context.Context, urls []string, eng types.RequestDoer) []types.Finding {
	var findings []types.Finding
	for _, url := range urls {
		for _, check := range pageRegistry {
			f := check.Run(ctx, url, eng)
			findings = append(findings, f...)
		}
	}
	return findings
}
