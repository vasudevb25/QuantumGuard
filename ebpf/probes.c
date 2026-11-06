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
    __u32 auid;         /* login uid: who originally logged in */
    __u64 dropped;      /* cumulative ring-buffer losses when this was sent */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/*
 * Events lost because the ring buffer was full. Only the kernel can count
 * these: userspace numbers what reaches it, so a loss here leaves no gap in
 * that numbering. Every event reports the running total and the collector
 * turns any increase into a sequence gap for CCA to attest.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

#define AUID_UNSET 0xFFFFFFFFu

/*
 * The login uid is set when a user logs in and survives sudo and su, so it
 * still names the person after the effective uid has become 0. System services
 * never logged in, so theirs is unset.
 */
static __always_inline __u32 login_uid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (!bpf_core_field_exists(task->loginuid))
        return AUID_UNSET;
    return BPF_CORE_READ(task, loginuid.val);
}

static __always_inline int emit(const char *filename, __u32 event_type)
{
    /*
     * Keep anything run by a login user or inside a login session, done
     * in-kernel so service noise never reaches the ring buffer. A uid test
     * alone would drop sudo's children and a root attacker's shell, the
     * activity this system most needs to see. capture/collector.py applies
     * the exact same check in userspace as defence in depth, so the two must
     * never disagree.
     *
     * Not covered: a root service that has been exploited and never had a
     * login session. Its uid is 0 and its login uid is unset, the same as
     * every other system service.
     *
     * This replaces an earlier version that instead only allowed comm
     * exactly "code", "python" or "bash" through - a hardcoded, IDE- and
     * workflow-specific allowlist that made the whole system unable to
     * see, for example, a poisoning attack launched as a "curl | sh"
     * one-liner. A provenance system that only watches processes an
     * attacker is unlikely to be named cannot make a completeness claim.
     */
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    __u32 auid = login_uid();

    if (uid < 1000 && auid == AUID_UNSET)
        return 0;

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    __u32 key = 0;
    __u64 *lost = bpf_map_lookup_elem(&drops, &key);

    if (!e) {
        if (lost)
            __sync_fetch_and_add(lost, 1);
        return 0;
    }

    e->dropped = lost ? *lost : 0;

    __u64 id = bpf_get_current_pid_tgid();

    e->timestamp = bpf_ktime_get_ns();
    e->pid = id >> 32;
    e->uid = uid;
    e->auid = auid;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read_user_str(
        e->filename,
        sizeof(e->filename),
        filename
    );

    e->event_type = event_type;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    return emit((const char *)ctx->args[0], 1);
}

/* execveat/fexecve run a program without ever calling execve(2). */
SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    return emit((const char *)ctx->args[1], 2);
}
