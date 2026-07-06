package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/RodKast/Vex/internal/checks"
	"github.com/RodKast/Vex/internal/crawler"
	"github.com/RodKast/Vex/internal/engine"
	"github.com/RodKast/Vex/pkg/types"
)

func main() {
	fmt.Println("Vex Starting...")
	target := flag.String("target", "", "Target URL or IP address to scan")
	timeout := flag.Int("timeout", 30, "Timeout in seconds for each request")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent requests to make")
	rateLimit := flag.Int("rate-limit", 100, "Maximum number of requests per second")

	flag.Parse()

	config := types.NewConfig()
	config.Target = *target
	config.Timeout = *timeout
	config.Concurrency = *concurrency
	config.RateLimit = *rateLimit

	fmt.Printf("Configuration: %+v\n", config)

	if config.Target == "" {
		fmt.Println("Error: -target flag is required")
		os.Exit(1)
	}

	ctx := context.Background()
	eng := engine.NewEngine(config)
	c := crawler.NewCrawler(eng, config)
	points := c.Crawl(ctx, config.Target)

	fmt.Printf("Found %d injection points\n", len(points))

	findings := checks.RunAll(ctx, points, eng)

	fmt.Printf("\n=== Findings (%d) ===\n", len(findings))
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Title + f.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Printf("[%s] %s - %s\n", f.Severity, f.Title, f.URL)
	}
}
