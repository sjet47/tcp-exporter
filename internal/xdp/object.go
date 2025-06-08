package xdp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"tcptrace/internal/conf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	LoadModeGeneric = "generic"
	LoadModeDriver  = "native"
	LoadModeOffload = "hw"
)

type xdpObj struct {
	Prog         *ebpf.Program `ebpf:"tcptrace"`
	RemapCfg     *ebpf.Map     `ebpf:"ipv4_remap_cfg"`
	CaptureCfg   *ebpf.Map     `ebpf:"ipv4_capture_cfg"`
	TrafficStats *ebpf.Map     `ebpf:"traffic_stats"`
}

func (obj *xdpObj) Close() {
	obj.Prog.Close()
	obj.RemapCfg.Close()
	obj.CaptureCfg.Close()
	obj.TrafficStats.Close()
}

type XDP struct {
	cfg     *conf.Conf
	obj     *xdpObj
	spec    *ebpf.CollectionSpec
	linkOpt link.XDPOptions

	l link.Link
}

func (x *XDP) Attach() error {
	err := x.loadConfigMap(x.cfg)
	if err != nil {
		return fmt.Errorf("setup config BPF map error: %v", err)
	}

	x.l, err = link.AttachXDP(x.linkOpt)
	if err != nil {
		return fmt.Errorf("attach xdp program to interface %s error: %v", x.cfg.NIC, err)
	}

	return nil
}

func (x *XDP) CountMap() (map[TrafficKey]CountValue, error) {
	return ReadCountMap(x.obj.TrafficStats, TrafficKeyParser, CountValueParser)
}

func (x *XDP) Close() {
	x.l.Close()
	x.obj.Close()
}

func (x *XDP) loadConfigMap(cfg *conf.Conf) error {
	for addr, cidrs := range cfg.Mapping {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid mapped IP address %q in mapping", addr)
		}
		for _, cidr := range cidrs {
			if err := remapSpec.PutCidrEntry(x.obj.RemapCfg, cidr, ip.To4()); err != nil {
				return fmt.Errorf("put remap entry for %s:%s error: %v", cidr, ip, err)
			}
		}
	}

	for ip, port := range cfg.Capture {
		portBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(portBytes, port)
		if err := captureSpec.PutCidrEntry(x.obj.CaptureCfg, ip, portBytes); err != nil {
			return fmt.Errorf("put capture entry for %s:%d error: %v", ip, port, err)
		}
	}

	return nil
}

func Load(prog io.ReaderAt, cfg *conf.Conf) (*XDP, error) {
	iface, err := net.InterfaceByName(cfg.NIC)
	if err != nil {
		return nil, fmt.Errorf("get nic name %q error: %v", cfg.NIC, err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(prog)
	if err != nil {
		return nil, fmt.Errorf("load xdp program error :%v", err)
	}

	obj := new(xdpObj)
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		return nil, fmt.Errorf("load and assign xdp object error: %v", err)
	}

	var flag link.XDPAttachFlags
	switch cfg.LoadMode {
	case LoadModeGeneric:
		flag = link.XDPGenericMode
	case LoadModeDriver:
		flag = link.XDPDriverMode
	case LoadModeOffload:
		flag = link.XDPOffloadMode
	default:
		flag = 0
	}

	if err := remapSpec.CheckMap(obj.RemapCfg); err != nil {
		return nil, fmt.Errorf("check remap map error: %v", err)
	}

	if err := captureSpec.CheckMap(obj.CaptureCfg); err != nil {
		return nil, fmt.Errorf("check capture map error: %v", err)
	}

	return &XDP{
		cfg:  cfg,
		obj:  obj,
		spec: spec,
		linkOpt: link.XDPOptions{
			Program:   obj.Prog,
			Interface: iface.Index,
			Flags:     flag,
		},
	}, nil
}
