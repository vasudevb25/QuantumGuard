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
    __u32 auid;
    __u64 dropped;
};

static void sig_int(int signo)
{
    exiting = 1;
}

/*
 * Process names and paths are attacker-controlled. Printed raw, a quote in a
 * file name produces invalid JSON and that exec never gets recorded, so
 * anything outside printable ASCII is escaped. Bytes >= 0x80 become \u00XX
 * because a path need not be valid UTF-8.
 */
static void print_json_string(const char *s, size_t max)
{
    size_t i;

    for (i = 0; i < max && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '"' || c == '\\')
            printf("\\%c", c);
        else if (c < 0x20 || c >= 0x7f)
            printf("\\u%04x", c);
        else
            putchar(c);
    }
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    printf("{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":\"",
           (unsigned long long)e->timestamp, e->pid, e->uid);
    print_json_string(e->comm, sizeof(e->comm));
    printf("\",\"file\":\"");
    print_json_string(e->filename, sizeof(e->filename));
    printf("\",\"type\":%u,\"auid\":%u,\"dropped\":%llu}\n",
           e->event_type, e->auid, (unsigned long long)e->dropped);

    fflush(stdout);

    return 0;
}
int main(void)
{
    struct probes *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

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
    fflush(stdout);

    while (!exiting)
        ring_buffer__poll(rb, 100);

    /* Losses after the last delivered event have no event to report them. */
    {
        __u32 key = 0;
        __u64 lost = 0;

        ring_buffer__consume(rb);
        if (!bpf_map__lookup_elem(skel->maps.drops, &key, sizeof(key),
                                  &lost, sizeof(lost), 0)) {
            printf("{\"final_dropped\":%llu}\n", (unsigned long long)lost);
            fflush(stdout);
        }
    }

cleanup:
    ring_buffer__free(rb);
    probes__destroy(skel);
    return err;
}