#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB buffer
} rb SEC(".maps");

SEC("xdp")
int xdp_packet_parser(struct xdp_md *ctx) {
    // get packet start and end addr
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }
    // check eth proto type
    if (eth->h_proto == bpf_htons(ETH_P_IP)) { // IPv4
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return XDP_ABORTED;
        }
        // check ip proto type
        if (ip->protocol == IPPROTO_TCP) { // TCP
            struct tcphdr *tcp = (void *)((void *)ip + (ip->ihl * 4));
            if ((void *)(tcp + 1) > data_end) {
                return XDP_ABORTED;
            }
            const int tcp_header_bytes = 20;

            if ((void *)tcp + tcp_header_bytes > data_end) {
                return XDP_PASS;
            }

            void *tcp_headers = bpf_ringbuf_reserve(&rb, tcp_header_bytes, 0);
            if (!tcp_headers) {
                return XDP_PASS;
            }

            for (int i = 0; i < tcp_header_bytes; i++) {
                unsigned char byte = *((unsigned char *)tcp + i);
                ((unsigned char *)tcp_headers)[i] = byte;
            }
            bpf_ringbuf_submit(tcp_headers, 0);
        }
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
