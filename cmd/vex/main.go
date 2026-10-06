package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/RodKast/Vex/internal/checks"
	"github.com/RodKast/Vex/internal/crawler"
	"github.com/RodKast/Vex/internal/engine"
	"github.com/RodKast/Vex/internal/output"
	"github.com/RodKast/Vex/pkg/types"
)

func main() {
	target := flag.String("target", "", "Target URL to scan (required)")
	timeout := flag.Int("timeout", 30, "Request timeout in seconds")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent requests")
	rateLimit := flag.Int("rate-limit", 100, "Max requests per second")
	cookie := flag.String("cookie", "", "Session cookie to include in requests")
	scope := flag.String("scope", "", "Allowed hostnames, comma-separated (default: target hostname)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "\033[31m"+`
██╗   ██╗███████╗██╗  ██╗
██║   ██║██╔════╝╚██╗██╔╝
██║   ██║█████╗   ╚███╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗
 ╚████╔╝ ███████╗██╔╝ ██╗
  ╚═══╝  ╚══════╝╚═╝  ╚═╝
`+"\033[0m")
		fmt.Fprint(os.Stderr, "\033[90mA web vulnerability scanner\033[0m\n\n")
		fmt.Fprint(os.Stderr, "\033[33mUSAGE:\033[0m\n")
		fmt.Fprint(os.Stderr, "  vex -target <url> [options]\n\n")
		fmt.Fprint(os.Stderr, "\033[33mOPTIONS:\033[0m\n")
		fmt.Fprint(os.Stderr, "  \033[32m-target\033[0m      Target URL to scan (required)\n")
		fmt.Fprint(os.Stderr, "  \033[32m-timeout\033[0m     Request timeout in seconds (default: 30)\n")
		fmt.Fprint(os.Stderr, "  \033[32m-concurrency\033[0m Number of concurrent requests (default: 10)\n")
		fmt.Fprint(os.Stderr, "  \033[32m-rate-limit\033[0m  Max requests per second (default: 100)\n")
		fmt.Fprint(os.Stderr, "  \033[32m-cookie\033[0m      Session cookie to include in requests\n")
		fmt.Fprint(os.Stderr, "  \033[32m-scope\033[0m       Allowed hostnames, comma-separated (default: target hostname)\n")
		fmt.Fprint(os.Stderr, "  \033[32m-verbose\033[0m     Enable verbose logging\n\n")
	}

	flag.Parse()

	fmt.Print("\033[31m" + `
██╗   ██╗███████╗██╗  ██╗
██║   ██║██╔════╝╚██╗██╔╝
██║   ██║█████╗   ╚███╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗
 ╚████╔╝ ███████╗██╔╝ ██╗
  ╚═══╝  ╚══════╝╚═╝  ╚═╝
` + "\033[0m")
	fmt.Println("\033[90mA web vulnerability scanner\033[0m")

	loglevel := slog.LevelInfo
	if *verbose {
		loglevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: loglevel,
	}))
	slog.SetDefault(logger)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "\033[31mError: -target flag is required\033[0m")
		fmt.Fprintln(os.Stderr, "Run 'vex -help' for usage.")
		os.Exit(1)
	}

	config := types.NewConfig()
	config.Target = *target
	config.Timeout = *timeout
	config.Concurrency = *concurrency
	config.RateLimit = *rateLimit
	config.Cookie = *cookie
	if *scope != "" {
		config.Scope = strings.Split(*scope, ",")
	} else {
		parsed, err := url.Parse(*target)
		if err == nil && parsed.Hostname() != "" {
			config.Scope = []string{parsed.Hostname()}
		}
	}

	slog.Info("VeX starting", "target", config.Target, "concurrency",
		config.Concurrency, "rate-limit", config.RateLimit)

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
