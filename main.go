package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"tcptrace/internal/conf"
	"tcptrace/internal/prom"
	"tcptrace/internal/xdp"

	"gopkg.in/yaml.v3"
)

//go:generate make -C ./xdp tcptrace.o
//go:embed xdp/tcptrace.o
var tcptraceProg []byte

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config.yaml>\n", os.Args[0])
		os.Exit(1)
	}

	f, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	cfg := new(conf.Conf)
	if err := yaml.Unmarshal(f, cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	x, err := xdp.Load(bytes.NewReader(tcptraceProg), cfg)
	if err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	defer x.Close()

	if err := x.Attach(); err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}

	// Start Prometheus metrics server
	metricsAddr := ":8080"
	if cfg.MetricsAddr != "" {
		metricsAddr = cfg.MetricsAddr
	}

	log.Printf("Starting Prometheus metrics server on %s", metricsAddr)
	if err := prom.StartMetricsServer(metricsAddr, x); err != nil {
		log.Fatalf("Failed to start metrics server: %v", err)
	}
}
