package checks

import (
	"context"
	"strings"
	"time"

	"github.com/RodKast/Vex/pkg/types"
)

type CMDiCheck struct{}

func (c *CMDiCheck) Name() string {
	return "Command Injection"
}

func (c *CMDiCheck) Run(ctx context.Context, point types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	payload := "; sleep 5"
	injectedURL := strings.Replace(point.URL, point.OriginalValue, payload, 1)

	resp := eng.Do(ctx, types.Request{URL: injectedURL, Method: point.Method})
	if resp.Error != nil {
		return nil
	}

	if resp.Elapsed > 4*time.Second {
		return []types.Finding{{
			Title:       "Command Injection",
			URL:         point.URL,
			Parameter:   point.Parameter,
			Severity:    "critical",
			Description: "Time-based command injection detected via sleep delay",
			Evidence:    payload,
			Confirmed:   true,
		}}
	}
	return nil
}

func init() {
	Register(&CMDiCheck{})
}
