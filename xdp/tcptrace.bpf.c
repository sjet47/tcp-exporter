// clang-format off
#include "vmlinux.h"
#include "if_ether.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

char _license[] SEC("license") = "GPL";

struct ipv4_cidr_key {
  __u32 prefixlen;  // CIDR prefix
  __u32 data;       // IPv4 network
};

// IPv4 Remapping config
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct ipv4_cidr_key);
  __type(value, __u32);  // remapped IPv4 address
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
#ifdef PIN_MAP
  __uint(pinning, LIBBPF_PIN_BY_NAME);  // Pin map to bpffs
#endif
} ipv4_remap_cfg SEC(".maps");

// Filter config
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct ipv4_cidr_key);
  __type(value, __be16);  // port
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
#ifdef PIN_MAP
  __uint(pinning, LIBBPF_PIN_BY_NAME);  // Pin map to bpffs
#endif
} ipv4_capture_cfg SEC(".maps");

// Traffic statistics
struct traffic_direction {
  __u32 src_ip;
  __u32 dst_ip;
};

struct count_value {
  __u64 bytes;
  __u64 pkts;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct traffic_direction);
  __type(value, struct count_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
} traffic_stats SEC(".maps");

// Increase the statistics of a map by one packet
static __always_inline void count_pkt(const void* key, __u64 value) {
  void* map = &traffic_stats;
  struct count_value* cnt = bpf_map_lookup_elem(map, key);
  if (NULL != cnt) {
    cnt->bytes += value;
    cnt->pkts++;
  } else {
    struct count_value count = {.bytes = value, .pkts = 1};
    bpf_map_update_elem(map, key, &count, BPF_NOEXIST);
  }
}

// Remap IPv4 address using the remap configuration
static __always_inline __u32 remap_ipv4(__u32 ipaddr) {
  struct ipv4_cidr_key key = {.prefixlen = 32, .data = ipaddr};
  __u32* remapped_ip = bpf_map_lookup_elem(&ipv4_remap_cfg, &key);
  if (NULL == remapped_ip) {
    return ipaddr;  // No remapping found, return original IP
  }
  return *remapped_ip;
}

// Check if the packet should be captured based on the configuration
static __always_inline bool capture(__u32 ipaddr, __be16 port) {
  struct ipv4_cidr_key key = {.prefixlen = 32, .data = ipaddr};
  __be16* capture_port = bpf_map_lookup_elem(&ipv4_capture_cfg, &key);
  if (NULL == capture_port) {
    return false;
  }
  __be16 cp = *capture_port;
  return cp == 0 || cp == port;
}

static __always_inline bool build_key(void* start,
                                      void* end,
                                      struct traffic_direction* key) {
  void* cursor = start;
  struct ethhdr* eth = cursor;
  __be16 l3_proto;
  struct iphdr* ip4hdr = NULL;
  __u8 l4_proto;
  struct tcphdr* tcphdr = NULL;

  // Assume the packet is Ethernet
  if (((void*)eth + sizeof(*eth)) > end) {
    return false;
  }
  l3_proto = bpf_ntohs(eth->h_proto);
  cursor += sizeof(*eth);

  // L3 protocol
  switch (l3_proto) {
    case ETH_P_IP:
      ip4hdr = cursor;
      if ((void*)ip4hdr + sizeof(*ip4hdr) > end) {
        return false;
      }
      l4_proto = ip4hdr->protocol;
      cursor += (ip4hdr->ihl << 2) & 0x3c;
      break;
    default:
      // Other l4 protocol is currently not supported
      return false;
  }

  if (l4_proto != IPPROTO_TCP) {
    return false;
  }

  tcphdr = cursor;
  if ((void*)tcphdr + sizeof(*tcphdr) > end) {
    return false;
  }

  if (!tcphdr->ack || (void*)(cursor + (tcphdr->doff << 2)) == end) {
    // This is an empty ACK packet, we do not count it
    return false;
  }

  if (capture(ip4hdr->daddr, tcphdr->dest) ||
      capture(ip4hdr->saddr, tcphdr->source)) {
#ifdef DEBUG
    bpf_printk("tcptrace: capture pkt[%u -> %u]", ip4hdr->saddr, ip4hdr->daddr);
#endif
    key->src_ip = remap_ipv4(ip4hdr->saddr);
    key->dst_ip = remap_ipv4(ip4hdr->daddr);
    return true;
  }
  return false;
}

SEC("xdp.tcptrace")
int tcptrace(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  __u64 len = (__u8*)data_end - (__u8*)data;

  struct traffic_direction key = {};
  if (build_key(data, data_end, &key)) {
    count_pkt(&key, len);
  }

  return XDP_PASS;
}
