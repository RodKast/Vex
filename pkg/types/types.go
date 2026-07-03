package types

import "time"

type Config struct {
	Target      string
	Timeout     int
	Concurrency int
	RateLimit   int
	Scope       []string
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

func NewConfig() Config {
	return Config{
		Timeout:     30,
		Concurrency: 10,
		RateLimit:   100,
		Scope:       []string{},
	}
}
