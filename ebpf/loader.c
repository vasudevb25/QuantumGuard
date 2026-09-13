#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include "probes.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[128];
    __u32 event_type;
};

static void sig_int(int signo)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    printf(
        "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"file\":\"%s\",\"type\":%u}\n",
        (unsigned long long)e->timestamp,
        e->pid,
        e->uid,
        e->comm,
        e->filename,
        e->event_type
    );

    fflush(stdout);

    return 0;
}
int main(void)
{
    struct probes *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_int);

    skel = probes__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }

    err = probes__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    err = probes__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Listening for execve events...\n");

    while (!exiting)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    probes__destroy(skel);
    return err;
}