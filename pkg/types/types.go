package types

type Config struct {
	Target      string
	Timeout     int
	Concurrency int
	RateLimit   int
	Scope       []string
}

func NewConfig() Config {
	return Config{
		Timeout:     30,
		Concurrency: 10,
		RateLimit:   100,
		Scope:       []string{},
	}
}
