package checks

import (
	"context"
	"testing"
	"time"

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

func TestXSSCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &XSSCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/search?q=test",
		Parameter:     "q",
		OriginalValue: "test",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/search?q=<script>vexqxss</script>": {
			URL:        "http://example.com/search?q=<script>vexqxss</script>",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("<html><body>Search results for <script>vexqxss</script></body></html>"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "Reflected XSS"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestXSSCheck_Run_NoXSS(t *testing.T) {
	ctx := context.Background()
	check := &XSSCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/search?q=test",
		Parameter:     "q",
		OriginalValue: "test",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/search?q=<script>vexqxss</script>": {
			URL:        "http://example.com/search?q=<script>vexqxss</script>",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("<html><body>Search results for test</body></html>"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}

func TestPathTraversalCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &PathTraversalCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/file?name=test.txt",
		Parameter:     "name",
		OriginalValue: "test.txt",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/file?name=../../../../etc/passwd": {
			URL:        "http://example.com/file?name=../../../../etc/passwd",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("root:x:0:0:root:/root:/bin/bash"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "Path Traversal"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestPathTraversalCheck_Run_NoTraversal(t *testing.T) {
	ctx := context.Background()
	check := &PathTraversalCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/file?name=test.txt",
		Parameter:     "name",
		OriginalValue: "test.txt",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/file?name=../../../../etc/passwd": {
			URL:        "http://example.com/file?name=../../../../etc/passwd",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("File not found"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}

func TestSQLiCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &SQLiCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/search?q=test",
		Parameter:     "q",
		OriginalValue: "test",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/search?q='": {
			URL:        "http://example.com/search?q='",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "SQL Injection"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestSQLiCheck_Run_NoSQLi(t *testing.T) {
	ctx := context.Background()
	check := &SQLiCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/search?q=test",
		Parameter:     "q",
		OriginalValue: "test",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/search?q='": {
			URL:        "http://example.com/search?q='",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("Search results for '"),
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}

func TestCMDiCheck_Run(t *testing.T) {
	ctx := context.Background()
	check := &CMDiCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/execute?cmd=test",
		Parameter:     "cmd",
		OriginalValue: "test",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/execute?cmd=; sleep 5": {
			URL:        "http://example.com/execute?cmd=; sleep 5",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("Command executed"),
			Elapsed:    5 * time.Second,
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	expectedTitle := "Command Injection"
	if findings[0].Title != expectedTitle {
		t.Errorf("Expected finding title '%s', got '%s'", expectedTitle, findings[0].Title)
	}
}

func TestCMDiCheck_Run_NoCMDi(t *testing.T) {
	ctx := context.Background()
	check := &CMDiCheck{}
	point := types.InjectionPoint{
		URL:           "http://example.com/execute?cmd=test",
		Parameter:     "cmd",
		OriginalValue: "test",
		Method:        "GET",
	}

	fakeResponses := map[string]types.Response{
		"http://example.com/execute?cmd=; sleep 5": {
			URL:        "http://example.com/execute?cmd=; sleep 5",
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       []byte("Command executed"),
			Elapsed:    1 * time.Second,
		},
	}

	fakeEng := &fakeDoer{Responses: fakeResponses}
	findings := check.Run(ctx, point, fakeEng)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}
