package prom

import (
	"fmt"
	"net"
	"net/http"

	"github.com/sjet47/tcp-exporter/internal/xdp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler creates a Prometheus metrics HTTP handler for XDP traffic statistics
func MetricsHandler(x *xdp.XDP) http.Handler {
	// Create registry and metrics once
	registry := prometheus.NewRegistry()

	// Create packet count metric
	packetCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcptrace_packets_total",
			Help: "Total number of packets observed by XDP program",
		},
		[]string{"direction", "peer"},
	)

	// Create byte count metric
	byteCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcptrace_bytes_total",
			Help: "Total number of bytes observed by XDP program",
		},
		[]string{"direction", "peer"},
	)

	registry.MustRegister(packetCounter)
	registry.MustRegister(byteCounter)

	// Create the base handler
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reset metrics before collecting new data
		packetCounter.Reset()
		byteCounter.Reset()

		// Get current traffic statistics from XDP
		countMap, err := x.CountMap()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read XDP statistics: %v", err), http.StatusInternalServerError)
			return
		}

		// Convert traffic statistics to Prometheus metrics
		for key, value := range countMap {
			direction := "inbound" // XDP program can only observe inbound traffic
			peer := net.IP(key.SrcIP[:]).String()
			packetCounter.WithLabelValues(direction, peer).Add(float64(value.PktCnt))
			byteCounter.WithLabelValues(direction, peer).Add(float64(value.ByteCnt))
		}

		// Serve the metrics
		handler.ServeHTTP(w, r)
	})
}

// StartMetricsServer starts an HTTP server serving Prometheus metrics
func StartMetricsServer(addr string, x *xdp.XDP) error {
	http.Handle("/metrics", MetricsHandler(x))
	return http.ListenAndServe(addr, nil)
}
