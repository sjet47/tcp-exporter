package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sjet47/tcp-exporter/internal/conf"
	"github.com/sjet47/tcp-exporter/internal/prom"
	"github.com/sjet47/tcp-exporter/internal/xdp"

	"gopkg.in/yaml.v3"
)

var (
	configPath  string
	genConfig   bool
	showVersion bool
)

func init() {
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&configPath, "c", "", "yaml configuration file path")
	flag.BoolVar(&genConfig, "gen", false, "generate default configuration file")
	flag.BoolVar(&showVersion, "v", false, "print version information and exit")
}

//go:generate make -C ./xdp tcptrace.o
//go:embed xdp/tcptrace.o
var tcptraceProg []byte

//go:embed version
var version string

func main() {
	flag.Parse()

	if showVersion {
		fmt.Fprintf(os.Stderr, "tcp-exporter %s\n", version)
		return
	}

	if genConfig {
		defaultConf := conf.Default()
		encoder := yaml.NewEncoder(os.Stdout)
		if err := encoder.Encode(defaultConf); err != nil {
			log.Fatalf("Failed to generate default config: %v", err)
		}
		return
	}

	if len(configPath) == 0 {
		flag.Usage()
		return
	}

	f, err := os.ReadFile(configPath)
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
