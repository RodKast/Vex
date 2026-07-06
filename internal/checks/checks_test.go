package checks

import (
	"context"
	"testing"

	"github.com/RodKast/Vex/pkg/types"
)

type fakeDoer struct {
	Responses map[string]types.Response
}

func (f *fakeDoer) Do(ctx context.Context, req types.Request) types.Response {
	if resp, ok := f.Responses[req.URL]; ok {
		return resp
	}
	return types.Response{
		URL:        req.URL,
		StatusCode: 404,
		Headers:    map[string]string{},
		Body:       []byte("Not Found"),
	}
}

func TestHeaderCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &HeaderCheck{}
	point := types.InjectionPoint{URL: "http://example.com"}

	fakeResponses := map[string]types.Response{
		"http://example.com": {
			URL:        "http://example.com",
			StatusCode: 200,
			Headers: map[string]string{
				"X-Frame-Options":           "DENY",
				"X-Content-Type-Options":    "nosniff",
				"Content-Security-Policy":   "default-src 'self'",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				// Missing X-XSS-Protection header
			},
			Body: []byte("OK"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "Missing Header: X-XSS-Protection"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestCookieCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &CookieCheck{}
	point := types.InjectionPoint{URL: "http://example.com"}

	fakeResponses := map[string]types.Response{
		"http://example.com": {
			URL:        "http://example.com",
			StatusCode: 200,
			Headers: map[string]string{
				"Set-Cookie": "sessionid=abc123; Path=/; HttpOnly",
				// Missing Secure flag
			},
			Body: []byte("OK"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "Insecure Cookie Flag: Secure"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestServerCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &ServerCheck{}
	point := types.InjectionPoint{URL: "http://example.com"}

	fakeResponses := map[string]types.Response{
		"http://example.com": {
			URL:        "http://example.com",
			StatusCode: 200,
			Headers: map[string]string{
				"Server": "Apache/2.4.41 (Ubuntu)",
			},
			Body: []byte("OK"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "Server Version Disclosure"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestServerCheck_Run_NoVersion(t *testing.T) {
	ctx := context.Background()
	check := &ServerCheck{}
	point := types.InjectionPoint{URL: "http://example.com"}

	fakeResponses := map[string]types.Response{
		"http://example.com": {
			URL:        "http://example.com",
			StatusCode: 200,
			Headers: map[string]string{
				"Server": "Apache",
			},
			Body: []byte("OK"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}

func TestDirListCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &DirListCheck{}
	point := types.InjectionPoint{URL: "http://example.com"}

	fakeResponses := map[string]types.Response{
		"http://example.com": {
			URL:        "http://example.com",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("<html><head><title>Index of /</title></head><body>Directory listing for /</body></html>"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "Directory Listing Enabled"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestDirListCheck_Run_NoDirListing(t *testing.T) {
	ctx := context.Background()
	check := &DirListCheck{}
	point := types.InjectionPoint{URL: "http://example.com"}

	fakeResponses := map[string]types.Response{
		"http://example.com": {
			URL:        "http://example.com",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("<html><head><title>Welcome</title></head><body>Welcome to our site!</body></html>"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}
