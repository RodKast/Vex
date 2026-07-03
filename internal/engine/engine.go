package engine

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/RodKast/Vex/pkg/types"
	"golang.org/x/time/rate"
)

type Engine struct {
	config  types.Config
	client  *http.Client
	limiter *rate.Limiter
}

func NewEngine(cfg types.Config) *Engine {
	return &Engine{
		config: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit),
			int(cfg.RateLimit)),
	}
}

func (e *Engine) Do(ctx context.Context, req types.Request) types.Response {
	start := time.Now()
	r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
	if err != nil {
		return types.Response{URL: req.URL, Error: err, Elapsed: time.Since(start)}
	}
	for key, val := range req.Headers {
		r.Header.Set(key, val)
	}
	if err := e.limiter.Wait(ctx); err != nil {
		return types.Response{URL: req.URL, Error: err, Elapsed: time.Since(start)}
	}
	resp, err := e.client.Do(r)
	if err != nil {
		return types.Response{URL: req.URL, Error: err, Elapsed: time.Since(start)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return types.Response{URL: req.URL, Error: err, Elapsed: time.Since(start)}
	}
	headers := map[string]string{}
	for key, vals := range resp.Header {
		headers[key] = vals[0]
	}
	return types.Response{
		URL:        req.URL,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
		Elapsed:    time.Since(start),
	}
}

func (e *Engine) Run(ctx context.Context, requests []types.Request) []types.Response {
	var responses []types.Response
	jobs := make(chan types.Request, len(requests))
	results := make(chan types.Response, len(requests))

	// Start worker goroutines
	for i := 0; i < e.config.Concurrency; i++ {
		go func() {
			for req := range jobs {
				results <- e.Do(ctx, req)
			}
		}()
	}

	// Send requests to the jobs channel
	go func() {
		for _, req := range requests {
			jobs <- req
		}
		close(jobs)
	}()

	// Collect results
	for i := 0; i < len(requests); i++ {
		responses = append(responses, <-results)
	}
	return responses

}
