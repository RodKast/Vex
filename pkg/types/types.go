package types

import (
	"context"
	"time"
)

type Config struct {
	Target      string
	Timeout     int
	Concurrency int
	RateLimit   int
	Scope       []string
	Cookie      string
}

type Request struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    []byte
}

type Response struct {
	URL        string
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Elapsed    time.Duration
	Error      error
}

type InjectionPoint struct {
	URL           string
	Parameter     string
	Type          string
	Method        string
	OriginalValue string
}

type Finding struct {
	Title       string
	URL         string
	Parameter   string
	Severity    string
	Description string
	Evidence    string
	Confirmed   bool
}

type VulnCheck interface {
	Name() string
	Run(ctx context.Context, point InjectionPoint, eng RequestDoer) []Finding
}

type RequestDoer interface {
	Do(ctx context.Context, req Request) Response
}

func NewConfig() Config {
	return Config{
		Timeout:     30,
		Concurrency: 10,
		RateLimit:   100,
		Scope:       []string{},
	}
}
