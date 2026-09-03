#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[128];
    __u32 event_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));

    /* Process filter */

    if (__builtin_memcmp(comm, "code", 4) != 0 &&
        __builtin_memcmp(comm, "python", 6) != 0 &&
        __builtin_memcmp(comm, "bash", 4) != 0)
        return 0;

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();

    e->timestamp = bpf_ktime_get_ns();
    e->pid = id >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();

    __builtin_memcpy(e->comm, comm, sizeof(comm));

    const char *filename = (const char *)ctx->args[0];

    bpf_probe_read_user_str(
        e->filename,
        sizeof(e->filename),
        filename
    );

    e->event_type = 1;

    bpf_ringbuf_submit(e, 0);

    return 0;
}