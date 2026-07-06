package checks

import (
	"context"
	"strings"

	"github.com/RodKast/Vex/pkg/types"
)

type CookieCheck struct{}

func (c *CookieCheck) Name() string {
	return "Insecure Cookie Flags"
}

func (c *CookieCheck) Run(ctx context.Context, point types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	resp := eng.Do(ctx, types.Request{URL: point.URL, Method: "GET"})
	if resp.Error != nil {
		return nil
	}

	var findings []types.Finding
	cookie := resp.Headers["Set-Cookie"]
	if cookie == "" {
		return nil
	}

	if !containsFlag(cookie, "Secure") {
		findings = append(findings, types.Finding{
			Title:       "Insecure Cookie Flag: Secure",
			URL:         point.URL,
			Severity:    "medium",
			Description: "Cookie is not set with the Secure flag",
			Confirmed:   true,
		})
	}

	if !containsFlag(cookie, "HttpOnly") {
		findings = append(findings, types.Finding{
			Title:       "Insecure Cookie Flag: HttpOnly",
			URL:         point.URL,
			Severity:    "medium",
			Description: "Cookie is not set with the HttpOnly flag",
			Confirmed:   true,
		})
	}

	return findings
}

func containsFlag(cookie, flag string) bool {
	return strings.Contains(cookie, flag)
}

func init() {
	Register(&CookieCheck{})
}
