package checks

import (
	"context"
	"net/url"
	"strings"

	"github.com/RodKast/Vex/pkg/types"
)

type XSSCheck struct{}

func (x *XSSCheck) Name() string {
	return "Reflected XSS"
}

func (x *XSSCheck) Run(ctx context.Context, point types.InjectionPoint,
	eng types.RequestDoer) []types.Finding {

	nonce := "vex" + point.Parameter + "xss"
	payload := "<script>" + nonce + "</script>"

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

	baseline := eng.Do(ctx, types.Request{
		URL:    baselineParsed.String(),
		Method: point.Method,
	})
	if baseline.Error != nil {
		return nil
	}

	resp := eng.Do(ctx, types.Request{
		URL:    injectedURL,
		Method: point.Method,
	})
	if resp.Error != nil {
		return nil
	}

	baselineBody := string(baseline.Body)
	injectedBody := string(resp.Body)
	if strings.Contains(injectedBody, nonce) && !strings.Contains(baselineBody, nonce) {
		return []types.Finding{{
			Title:       "Reflected XSS",
			URL:         point.URL,
			Parameter:   point.Parameter,
			Severity:    "high",
			Description: "Parameter reflects user input without encoding",
			Evidence:    payload,
			Confirmed:   true,
		}}
	}
	return nil
}

func init() {
	Register(&XSSCheck{})
}
