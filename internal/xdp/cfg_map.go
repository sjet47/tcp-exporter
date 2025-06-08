package xdp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

var (
	remapSpec = mapSpec{
		Type:      ebpf.LPMTrie,
		KeySize:   8, // Prefix(4) + IPv4Addr(4)
		ValueSize: 4, // IPv4Addr(4)
	}

	captureSpec = mapSpec{
		Type:      ebpf.LPMTrie,
		KeySize:   8, // Prefix(4) + IPv4Addr(4)
		ValueSize: 2, // Tcp Port(2)
	}
)

type mapSpec struct {
	Type      ebpf.MapType
	KeySize   uint32
	ValueSize uint32
}

func (ms *mapSpec) CheckMap(m *ebpf.Map) error {
	if m.Type() != ebpf.LPMTrie {
		return fmt.Errorf("expected map type %s, got %s", ms.Type, m.Type())
	}

	if ms.KeySize != m.KeySize() {
		return fmt.Errorf("expected key size to be %d, got %d", ms.KeySize, m.KeySize())
	}

	if ms.ValueSize != m.ValueSize() {
		return fmt.Errorf("expected value size to be %d, got %d", ms.ValueSize, m.ValueSize())
	}

	return nil
}

func (ms *mapSpec) CheckEntry(key, value []byte) error {
	if len(key) != int(ms.KeySize) {
		return fmt.Errorf("expected key size to be %d, got %d", ms.KeySize, len(key))
	}

	if len(value) != int(ms.ValueSize) {
		return fmt.Errorf("expected value size to be %d, got %d", ms.ValueSize, len(value))
	}

	return nil
}

func (ms *mapSpec) PutCidrEntry(m *ebpf.Map, cidr string, value []byte) error {
	key, err := cidrToTrieKey(cidr)
	if err != nil {
		return fmt.Errorf("cidr to trie key error: %w", err)
	}

	if err := ms.CheckEntry(key, value); err != nil {
		return fmt.Errorf("check entry error: %w", err)
	}

	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("put to trie map error: %w", err)
	}

	return nil
}

func (ms *mapSpec) PutCidrEntries(m *ebpf.Map, entries map[string][]byte) error {
	if err := ms.CheckMap(m); err != nil {
		return fmt.Errorf("check map error: %w", err)
	}

	keys := make([][]byte, 0, len(entries))
	values := make([][]byte, 0, len(entries))

	for cidr, value := range entries {
		key, err := cidrToTrieKey(cidr)
		if err != nil {
			return fmt.Errorf("cidr %q to trie key error: %w", cidr, err)
		}
		if err := ms.CheckEntry(key, value); err != nil {
			return fmt.Errorf("check entry error: %w", err)
		}
		keys = append(keys, key)
		values = append(values, value)
	}

	n, err := m.BatchUpdate(keys, values, nil)
	if err != nil {
		if n == 0 {
			return fmt.Errorf("batch update to trie map error: %w", err)
		}
		return fmt.Errorf("batch update to trie map error, only %d/%d entries updated: %w", n, len(entries), err)
	}
	return nil
}

// The first 4 bytes represent the prefix length, and following bytes represent
// the IP address.
// There is 2 possible length, 4+4 bytes for IPv4, and 4+16 bytes for IPv6.
func cidrToTrieKey(cidr string) ([]byte, error) {
	ip, mask, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	prefixLen, bitLen := mask.Mask.Size()
	if bitLen != 32 {
		return nil, fmt.Errorf("only IPv4 CIDR are supported, got %s", cidr)
	}
	ip = ip.To4()

	return append(binary.NativeEndian.AppendUint32(make([]byte, 0, 4+bitLen/8),
		uint32(prefixLen)), ip...), nil
}
