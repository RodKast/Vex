package main

import (
	"flag"
	"fmt"

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
}
