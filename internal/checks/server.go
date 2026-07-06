package checks

import (
	"context"
	"regexp"

	"github.com/RodKast/Vex/pkg/types"
)

type ServerCheck struct{}

func (s *ServerCheck) Name() string {
	return "Server Version Disclosure"
}

func (s *ServerCheck) Run(ctx context.Context, point types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	resp := eng.Do(ctx, types.Request{
		URL:    point.URL,
		Method: "GET"})
	if resp.Error != nil {
		return nil
	}

	server := resp.Headers["Server"]
	if server == "" {
		return nil
	}

	versionPattern := regexp.MustCompile(`\d+\.\d+`)
	if versionPattern.MatchString(server) {
		return []types.Finding{
			{
				Title:     "Server Version Disclosure",
				URL:       point.URL,
				Parameter: point.URL,
				Severity:  "low",
				Evidence:  server,
				Confirmed: true,
			},
		}
	}
	return nil
}

func init() {
	Register(&ServerCheck{})
}
