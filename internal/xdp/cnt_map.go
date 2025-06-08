package xdp

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

type adder[T any] interface {
	Add(T) T
}

type parser[T any] interface {
	Parse([]byte) T
	Size() uint32
}

var TrafficKeyParser parser[TrafficKey] = trafficKeyParser(0)
var CountValueParser parser[adder[CountValue]] = countValueParser(0)

func ReadCountMap[K comparable, V any, A adder[V]](
	m *ebpf.Map,
	keyParser parser[K],
	valueParser parser[A],
) (map[K]V, error) {
	if typ := m.Type(); typ != ebpf.PerCPUHash {
		return nil, fmt.Errorf("expected map type Hash(1) or PerCPUHash(5), got %s", m.Type())
	}

	if keyParser.Size() != m.KeySize() {
		return nil, fmt.Errorf("expected key size to be %d, got %d", keyParser.Size(), m.KeySize())
	}

	if valueParser.Size() != m.ValueSize() {
		return nil, fmt.Errorf("expected value size to be %d, got %d", valueParser.Size(), m.ValueSize())
	}

	result := make(map[K]V)
	iter := m.Iterate()
	key := make([]byte, int(m.KeySize()))

	values := make([][]byte, ebpf.MustPossibleCPU())
	for i := range values {
		values[i] = make([]byte, int(m.ValueSize()))
	}
	for iter.Next(&key, &values) {
		for _, value := range values {
			key := keyParser.Parse(key)
			result[key] = valueParser.Parse(value).Add(result[key])
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

type TrafficKey struct {
	SrcIP [4]byte
	DstIP [4]byte
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
		SrcIP: [4]byte(key[:4]),
		DstIP: [4]byte(key[4:]),
	}
}

func (p trafficKeyParser) Size() uint32 {
	return 8
}

type countValueParser int

func (p countValueParser) Parse(value []byte) adder[CountValue] {
	return CountValue{
		ByteCnt: binary.LittleEndian.Uint64(value[:8]),
		PktCnt:  binary.LittleEndian.Uint64(value[8:]),
	}
}

func (p countValueParser) Size() uint32 {
	return 16
}
