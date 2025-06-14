package xdp

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
)

var (
	remapSpec = MapSpec{
		Type:      ebpf.LPMTrie,
		KeySize:   8, // prefix(4) + ipv4_addr(4)
		ValueSize: 4, // ipv4_addr(4)
	}

	captureSpec = MapSpec{
		Type:      ebpf.Array,
		KeySize:   4, // tcp_dst_port(4)
		ValueSize: 1, // bool
	}

	statsSpec = MapSpec{
		Type:      ebpf.Hash,
		KeySize:   8,  // src_ip(4) + dst_port_be(4)
		ValueSize: 16, // bytes(8) + pkts(8)
	}
)

var trafficKey Parser[TrafficKey] = trafficKeyParser(0)
var countValue Parser[Adder[CountValue]] = countValueParser(0)

type TrafficKey struct {
	SrcIP   [4]byte
	DstPort uint32
}

type CountValue struct {
	ByteCnt uint64
	PktCnt  uint64
}

func (lhs CountValue) Add(rhs CountValue) CountValue {
	return CountValue{
		ByteCnt: lhs.ByteCnt + rhs.ByteCnt,
		PktCnt:  lhs.PktCnt + rhs.PktCnt,
	}
}

type trafficKeyParser int

func (p trafficKeyParser) Parse(key []byte) TrafficKey {
	return TrafficKey{
		SrcIP:   [4]byte(key[:4]),
		DstPort: binary.NativeEndian.Uint32(key[4:]),
	}
}

// 0b 10000010 00100011
// 0b0010001110000010

func (p trafficKeyParser) Size() uint32 {
	return 8
}

type countValueParser int

func (p countValueParser) Parse(value []byte) Adder[CountValue] {
	return CountValue{
		ByteCnt: binary.NativeEndian.Uint64(value[:8]),
		PktCnt:  binary.NativeEndian.Uint64(value[8:]),
	}
}

func (p countValueParser) Size() uint32 {
	return 16
}
