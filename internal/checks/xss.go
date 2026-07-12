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
	params.Set(point.Parameter, payload)
	parsed.RawQuery = params.Encode()
	injectedURL := parsed.String()

	resp := eng.Do(ctx, types.Request{
		URL:    injectedURL,
		Method: point.Method,
	})
	if resp.Error != nil {
		return nil
	}

	if strings.Contains(string(resp.Body), nonce) {

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
