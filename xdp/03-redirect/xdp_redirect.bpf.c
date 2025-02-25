#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

// client
int client_ip = bpf_htonl(0xac12c05a); // 172.18.192.90
unsigned char client_mac[6] = {0x3c, 0x22, 0xfb, 0x98, 0x15, 0x21};
// backend
int backend_ip = bpf_htonl(0xac12eab2); // 172.18.234.178
unsigned char backend_mac[6] = {0x0, 0xc, 0x29, 0x55, 0xe2, 0xb2};
// load balence
int lb_ip = bpf_htonl(0xac1210a2); // 172.18.16.162
unsigned char lb_mac[6] = {0xd8, 0xbb, 0xc1, 0xbb, 0x76, 0x76};

static __always_inline __u16
csum_fold_helper(__u64 csum) {
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

// eBPF 程序入口
SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // 检查以太网头部是否合法
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    // 只处理 IPv4 数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    // 检查 IP 头部是否合法
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (iph->saddr == client_ip) {
        iph->daddr = backend_ip;
        __builtin_memcpy(eth->h_dest, backend_mac, 6);

        iph->saddr = lb_ip;
        __builtin_memcpy(eth->h_source, lb_mac, 6);
        // 重新计算 IP 校验和
        iph->check = 0;  // 校验和需要重新计算
        iph->check = iph_csum(iph);
        bpf_printk("Receive TCP packet from client");
        return XDP_TX;
    }
    if (iph->saddr == backend_ip) {
        iph->daddr = client_ip;
        __builtin_memcpy(eth->h_dest, client_mac, 6);

        iph->saddr = lb_ip;
        __builtin_memcpy(eth->h_source, lb_mac, 6);
        // 重新计算 IP 校验和
        iph->check = 0;  // 校验和需要重新计算
        iph->check = iph_csum(iph);
        bpf_printk("Receive TCP packet from backend");
        return XDP_TX;
    }

    return XDP_PASS;
}

// 指定许可证
char _license[] SEC("license") = "GPL";
