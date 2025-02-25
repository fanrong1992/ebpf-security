#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

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
            // example: record TCP src port and dst port
            bpf_printk("TCP src port: %d, dst port: %d", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        } else if (ip->protocol == IPPROTO_UDP) { // UDP
            struct udphdr *udp = (void *)((void *)ip + (ip->ihl * 4));
            if ((void *)(udp + 1) > data_end) {
                return XDP_ABORTED;
            }
            bpf_printk("UDP src port: %d, dst port: %d", bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
        }
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
