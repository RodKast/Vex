package checks

import (
	"context"
	"strings"

	"github.com/RodKast/Vex/pkg/types"
)

type DirListCheck struct{}

func (d *DirListCheck) Name() string {
	return "Directory Listing"
}

func (d *DirListCheck) Run(ctx context.Context, point types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	resp := eng.Do(ctx, types.Request{
		URL:    point.URL,
		Method: "GET"})
	if resp.Error != nil {
		return nil
	}

	if resp.StatusCode == 200 && isDirectoryListing(resp.Body) {
		return []types.Finding{
			{
				Title:     "Directory Listing Enabled",
				URL:       point.URL,
				Parameter: point.URL,
				Severity:  "medium",
				Evidence:  string(resp.Body),
				Confirmed: true,
			},
		}
	}
	return nil
}

func isDirectoryListing(body []byte) bool {
	content := string(body)
	return strings.Contains(content, "Index of /") ||
		strings.Contains(content, "<title>Index of") ||
		strings.Contains(content, "Directory listing for")
}

func init() {
	Register(&DirListCheck{})
}
