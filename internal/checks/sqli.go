package checks

import (
	"context"
	"net/url"
	"strings"

	"github.com/RodKast/Vex/pkg/types"
)

type SQLiCheck struct{}

func (s *SQLiCheck) Name() string {
	return "SQL Injection"
}

func (s *SQLiCheck) Run(ctx context.Context, point types.InjectionPoint, eng types.RequestDoer) []types.Finding {
	payload := "'"
	parsed, err := url.Parse(point.URL)
	if err != nil {
		return nil
	}
	params := parsed.Query()
	for k, v := range point.FormParams {
		params.Set(k, v)
	}
	params.Set(point.Parameter, payload)
	parsed.RawQuery = params.Encode()
	injectedURL := parsed.String()

	baselineParsed, _ := url.Parse(point.URL)
	baselineParams := baselineParsed.Query()
	for k, v := range point.FormParams {
		baselineParams.Set(k, v)
	}
	baselineParsed.RawQuery = baselineParams.Encode()

	baseline := eng.Do(ctx, types.Request{URL: baselineParsed.String(), Method: point.Method})
	if baseline.Error != nil {
		return nil
	}

	resp := eng.Do(ctx, types.Request{URL: injectedURL, Method: point.Method})
	if resp.Error != nil {
		return nil
	}

	errorSignatures := []string{
		"SQL syntax", "mysql_fetch", "ORA-", "syntax error",
		"mysql_num_rows", "Warning: mysql",
	}

	body := string(resp.Body)
	for _, sig := range errorSignatures {
		if strings.Contains(body, sig) && !strings.Contains(string(baseline.Body), sig) {
			return []types.Finding{{
				Title:       "SQL Injection",
				URL:         point.URL,
				Parameter:   point.Parameter,
				Severity:    "critical",
				Description: "SQL error detected in response",
				Evidence:    sig,
				Confirmed:   true,
			}}
		}
	}
	return nil
}

func init() {
	Register(&SQLiCheck{})
}
