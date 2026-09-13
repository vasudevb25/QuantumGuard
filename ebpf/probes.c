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
    /*
     * Real-user filter, done in-kernel so system/service accounts never
     * even reach the ring buffer. uid < 1000 is the login-user threshold
     * on virtually every Linux distribution; capture/collector.py applies
     * the exact same check again in userspace as defence in depth, so the
     * two must never disagree.
     *
     * This replaces an earlier version that instead only allowed comm
     * exactly "code", "python" or "bash" through - a hardcoded, IDE- and
     * workflow-specific allowlist that made the whole system unable to
     * see, for example, a poisoning attack launched as a "curl | sh"
     * one-liner. A provenance system that only watches processes an
     * attacker is unlikely to be named cannot make a completeness claim.
     */
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    if (uid < 1000)
        return 0;

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();

    e->timestamp = bpf_ktime_get_ns();
    e->pid = id >> 32;
    e->uid = uid;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

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