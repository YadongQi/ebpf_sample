#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "kvm_dump.h"
#include "kvm_dump.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16

int libbpf_print_fn(enum libbpf_print_level level,
        const char *format, va_list args)
{   
    if (level == LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}


/* Function to be invoked at sys_fchmodat triggered */
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct data_t *info = data;

    printf("%-8d 0x%-16llx 0x%-4x 0x%-16llx\n", info->pid,
            info->root_hpa, info->root_level, info->eptp);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(void) {
    struct perf_buffer *pb = NULL;
    struct kvm_dump_bpf *obj;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = kvm_dump_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = kvm_dump_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = kvm_dump_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("%-8s %-16s %-4s %-16s\n", "PID", "ROOT_HPA", "ROOT_LEVEL", "EPTP");

    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			  handle_event, handle_lost_events, NULL, NULL);

    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    while ((err = perf_buffer__poll(pb, 100)) >= 0)
        ;

cleanup:
    perf_buffer__free(pb);
    kvm_dump_bpf__destroy(obj);

    return err != 0;
}
