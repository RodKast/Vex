package checks

import (
	"context"

	"github.com/RodKast/Vex/pkg/types"
)

type HeaderCheck struct{}

func (h *HeaderCheck) Name() string {
	return "Missing Security Headers"
}

func (h *HeaderCheck) Run(ctx context.Context, point types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	resp := eng.Do(ctx, types.Request{URL: point.URL, Method: "GET"})
	if resp.Error != nil {
		return nil
	}
	securityHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-XSS-Protection",
	}

	var findings []types.Finding
	for _, header := range securityHeaders {
		if resp.Headers[header] == "" {
			findings = append(findings, types.Finding{
				Title:       "Missing Header: " + header,
				URL:         point.URL,
				Severity:    "low",
				Description: header + " header is not set",
				Confirmed:   true,
			})
		}
	}
	return findings
}

func init() {
	Register(&HeaderCheck{})
}
