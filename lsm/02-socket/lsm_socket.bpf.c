#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM  1
#define AF_INET 2

const __u32 blockip = 0xac12c05a;

SEC("lsm/socket_connect")
int BPF_PROG(restricted_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (address->sa_family == AF_INET) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        //struct in_addr d = BPF_CORE_READ(addr, sin_addr);
    
        if (addr->sin_addr.s_addr == bpf_htonl(blockip)) {
            bpf_printk("[LSM] PID: %d, Block ip: 0x%x connect", pid, addr->sin_addr.s_addr);
            return -EPERM;
        }
    }
    return 0;
}
