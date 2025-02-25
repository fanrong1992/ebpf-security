#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EACCES  13
#define BLOCKED_FS "tmpfs"


SEC("lsm/sb_mount")
int BPF_PROG(restricted_mount, const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data)
{
    if (type != NULL) {
        char kbuf[6] = "";
        bpf_probe_read_kernel(kbuf, 5, type);
        if (bpf_strncmp(kbuf, 5, BLOCKED_FS) == 0) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            bpf_printk("[LSM] PID %d, Block mount of filesystem type: %s", pid, kbuf);
            return -EACCES;
        }
    }
    return 0;
}
