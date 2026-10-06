package engine

import (
	"testing"
	"context"
	"time"

	"github.com/RodKast/Vex/pkg/types"
)

func TestInScope(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		scope []string
		want  bool
	}{
		{"in scope exact match", "https://example.com/path", []string{"example.com"}, true},
		{"out of scope", "https://evil.com/path", []string{"example.com"}, false},
		{"empty scope allows all", "https://anything.com", []string{}, true},
		{"subdomain not allowed", "https://sub.example.com/path", []string{"example.com"}, false},
		{"invalid url", "not-a-url", []string{"example.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := types.NewConfig()
			cfg.Scope = tt.scope
			e := NewEngine(cfg)

			got := e.inScope(tt.url)
			if got != tt.want {
				t.Errorf("inScope(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestRunRespectsContextCancellation(t *testing.T) {
	cfg := types.NewConfig()
	cfg.Concurrency = 2
	cfg.RateLimit = 10
	cfg.Timeout = 5
	e := NewEngine(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	requests := []types.Request{
		{URL: "https://example.com", Method: "GET"},
		{URL: "https://example.com/page2", Method: "GET"},
	}

	done := make(chan struct{})
	go func() {
		e.Run(ctx, requests)
		close(done)
	}()

	cancel() // cancel immediately

	select {
	case <-done:
		// Run returned after cancellation — correct
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancellation — likely blocked")
	}
}