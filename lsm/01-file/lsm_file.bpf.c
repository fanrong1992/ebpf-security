#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM  1
#define MAX_PATH 256

SEC("lsm/file_open")
int BPF_PROG(restricted_file_open, struct file *file)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char filename[MAX_PATH];
    if (bpf_d_path(&file->f_path, filename, MAX_PATH) < 0) {
        bpf_printk("[LSM] Parse filename failed!");
        return 0;
    }
    char *target = "/home/fanrong/orig";
    if (bpf_strncmp(filename, 18, target) == 0) {
        bpf_printk("[LSM] PID: %d, Block file: %s open", pid, filename);
        return -EPERM;
    }
    return 0;
}
