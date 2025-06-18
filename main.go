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
	configPath    string
	kernalVersion string
	genConfig     bool
	showVersion   bool
)

func init() {
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&configPath, "c", "", "yaml configuration file path")
	flag.StringVar(&kernalVersion, "kernel", "5.15", "kernel version to use for XDP program (default: 5.15)")
	flag.BoolVar(&genConfig, "gen", false, "generate default configuration file")
	flag.BoolVar(&showVersion, "v", false, "print version information and exit")
}

//go:generate make CFLAGS='-DPER_CPU' -C ./xdp tcptrace.o.6.15
//go:embed xdp/6.15/tcptrace.o
var tcptraceProg_6_15 []byte

//go:generate make CFLAGS='-DPER_CPU' -C ./xdp tcptrace.o.5.15
//go:embed xdp/5.15/tcptrace.o
var tcptraceProg_5_15 []byte

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

	var prog []byte
	switch kernalVersion {
	case "6.15":
		prog = tcptraceProg_6_15
	case "5.15":
		prog = tcptraceProg_5_15
	default:
		log.Fatalf("Unsupported kernel version: %s", kernalVersion)
	}

	x, err := xdp.Load(bytes.NewReader(prog), cfg)
	if err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	defer x.Close()

	if err := x.Attach(); err != nil {
		log.Panicf("Failed to attach XDP program: %v", err)
	}

	// Start Prometheus metrics server
	metricsAddr := ":8080"
	if cfg.MetricsAddr != "" {
		metricsAddr = cfg.MetricsAddr
	}

	log.Printf("Starting Prometheus metrics server on %s", metricsAddr)
	if err := prom.StartMetricsServer(metricsAddr, x); err != nil {
		log.Panicf("Failed to start metrics server: %v", err)
	}
}
