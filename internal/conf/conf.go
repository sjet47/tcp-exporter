package conf

type Conf struct {
	NIC         string              `yaml:"nic,omitempty"`          // Interface to apply the configuration
	LoadMode    string              `yaml:"load_mode,omitempty"`    // Load mode for the XDP program (e.g., "generic", "driver", "offload")
	MetricsAddr string              `yaml:"metrics_addr,omitempty"` // Address for the metrics server
	Mapping     map[string][]string `yaml:"mapping,omitempty"`      // Mapping of keys to values
	Capture     map[string]uint16   `yaml:"capture,omitempty"`      // Capture configuration, key is the interface name, value is the capture mode
}
