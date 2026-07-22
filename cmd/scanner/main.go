package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/RodKast/Vex/internal/checks"
	"github.com/RodKast/Vex/internal/crawler"
	"github.com/RodKast/Vex/internal/engine"
	"github.com/RodKast/Vex/internal/output"
	"github.com/RodKast/Vex/pkg/types"
)

func main() {
	fmt.Println("Vex Starting...")
	target := flag.String("target", "", "Target URL or IP address to scan")
	timeout := flag.Int("timeout", 30, "Timeout in seconds for each request")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent requests to make")
	rateLimit := flag.Int("rate-limit", 100, "Maximum number of requests per second")
	cookie := flag.String("cookie", "", "Session cookie to include in requests")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")


	flag.Parse()

	loglevel := slog.LevelInfo
	if *verbose {
		loglevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: loglevel,
	}))
	slog.SetDefault(logger)

	config := types.NewConfig()
	config.Target = *target
	config.Timeout = *timeout
	config.Concurrency = *concurrency
	config.RateLimit = *rateLimit
	config.Cookie = *cookie
	slog.Info("VeX starting", "target", config.Target, "concurrency", 
	config.Concurrency, "rate-limit", config.RateLimit)

	if config.Target == "" {
		fmt.Println("Error: -target flag is required")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt signal, shutting down...")
		cancel()
	}()

	eng := engine.NewEngine(config)
	c := crawler.NewCrawler(eng, config)
	points := c.Crawl(ctx, config.Target)

	slog.Info("Crawl complete", "injection_points", len(points))

	findings := checks.RunAll(ctx, points, eng)

	output.PrintFindings(findings)
	output.PrintSummary(findings)
}
