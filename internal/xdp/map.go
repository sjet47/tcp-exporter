package xdp

import (
	"encoding/binary"
	"fmt"
	"iter"
	"log"
	"net"

	"github.com/cilium/ebpf"
)

type MapSpec struct {
	Type      ebpf.MapType
	KeySize   uint32
	ValueSize uint32
}

func (ms *MapSpec) WithMap(m *ebpf.Map) (*Map, error) {
	if m.Type() != ms.Type {
		return nil, fmt.Errorf("expected map type %s, got %s", ms.Type, m.Type())
	}

	if ms.KeySize != m.KeySize() {
		return nil, fmt.Errorf("expected key size to be %d, got %d", ms.KeySize, m.KeySize())
	}

	if ms.ValueSize != m.ValueSize() {
		return nil, fmt.Errorf("expected value size to be %d, got %d", ms.ValueSize, m.ValueSize())
	}

	return &Map{
		m: m,
	}, nil
}

type Map struct {
	m *ebpf.Map
}

func (m *Map) IterEntry() iter.Seq2[[]byte, []byte] {
	return func(yield func([]byte, []byte) bool) {
		miter := m.m.Iterate()
		key := make([]byte, int(m.m.KeySize()))
		value := make([]byte, int(m.m.ValueSize()))

		for miter.Next(&key, &value) {
			if !yield(key, value) {
				return
			}
		}

		if err := miter.Err(); err != nil {
			log.Printf("map iteration error: %v", err)
		}
	}
}

func (m *Map) PutEntry(key []byte, value []byte) error {
	if err := m.checkEntry(key, value); err != nil {
		return fmt.Errorf("check entry error: %w", err)
	}

	if err := m.m.Put(key, value); err != nil {
		return fmt.Errorf("put entry to map error: %w", err)
	}

	return nil
}

func (m *Map) PutCidrEntry(cidr string, value []byte) error {
	key, err := cidrToTrieKey(cidr)
	if err != nil {
		return fmt.Errorf("cidr to trie key error: %w", err)
	}

	if err := m.checkEntry(key, value); err != nil {
		return fmt.Errorf("check entry error: %w", err)
	}

	return m.PutEntry(key, value)
}

func (m *Map) checkEntry(key, value []byte) error {
	if len(key) != int(m.m.KeySize()) {
		return fmt.Errorf("expected key size to be %d, got %d", m.m.KeySize(), len(key))
	}

	if len(value) != int(m.m.ValueSize()) {
		return fmt.Errorf("expected value size to be %d, got %d", m.m.ValueSize(), len(value))
	}

	return nil
}

type Adder[T any] interface {
	Add(T) T
}

type Parser[T any] interface {
	Parse([]byte) T
	Size() uint32
}

func ReadMergeMap[K comparable, V any, A Adder[V]](
	m *Map,
	keyParser Parser[K],
	valueParser Parser[A],
) (map[K]V, error) {
	result := make(map[K]V)
	for key, value := range m.IterEntry() {
		key := keyParser.Parse(key)
		result[key] = valueParser.Parse(value).Add(result[key])
	}
	return result, nil
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
