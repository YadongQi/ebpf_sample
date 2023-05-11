#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kvm_dump.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * Use following method to fetch event you want to probe:
 *
 * #cat /proc/kallsyms | grep construct_eptp
 * 0000000000000000 t construct_eptp
 *
 *
 */
SEC("kprobe/construct_eptp")
int construct_eptp(struct pt_regs *ctx) {
    u64 root_hpa = (u64)PT_REGS_PARM2(ctx);
    int root_level = PT_REGS_PARM3(ctx);
    u64 eptp = PT_REGS_RET(ctx);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t data = {};

    data.pid = pid;
    data.root_hpa = root_hpa;
    data.root_level = root_level;
    data.eptp = eptp;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
