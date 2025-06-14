package conf

type Conf struct {
	NIC         string              `yaml:"nic,omitempty"`          // Interface to apply the configuration
	LoadMode    string              `yaml:"load_mode,omitempty"`    // Load mode for the XDP program (e.g., "generic", "native", "hw")
	MetricsAddr string              `yaml:"metrics_addr,omitempty"` // Address for the metrics server
	Mapping     map[string][]string `yaml:"mapping,omitempty"`      // Mapping of keys to values
	Capture     []uint32            `yaml:"capture,omitempty"`      // Capture configuration, key is the interface name, value is the capture mode
}

func Default() *Conf {
	return &Conf{
		NIC:         "eth0",
		LoadMode:    "native|generic|hw",
		MetricsAddr: ":8080",
		Mapping: map[string][]string{
			"192.168.5.0": {"192.168.5.1/24"},
		},
		Capture: []uint32{80, 443},
	}
}
