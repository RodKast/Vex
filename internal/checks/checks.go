package checks

import (
	"context"

	"github.com/RodKast/Vex/pkg/types"
)

var registry []types.VulnCheck

func Register(c types.VulnCheck) {
	registry = append(registry, c)
}

func RunAll(ctx context.Context, points []types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	var findings []types.Finding
	for _, point := range points {
		for _, check := range registry {
			f := check.Run(ctx, point, eng)
			findings = append(findings, f...)
		}
	}
	return findings
}
