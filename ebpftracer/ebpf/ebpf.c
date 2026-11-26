#include <uapi/linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define EVENT_TYPE_PROCESS_START	    1
#define EVENT_TYPE_PROCESS_EXIT		    2
#define EVENT_TYPE_CONNECTION_OPEN	    3
#define EVENT_TYPE_CONNECTION_CLOSE	    4
#define EVENT_TYPE_CONNECTION_ERROR	    5
#define EVENT_TYPE_LISTEN_OPEN		    6
#define EVENT_TYPE_LISTEN_CLOSE 	    7
#define EVENT_TYPE_FILE_OPEN		    8
#define EVENT_TYPE_TCP_RETRANSMIT	    9
#define EVENT_TYPE_PYTHON_THREAD_LOCK	11

#define EVENT_REASON_OOM_KILL		1

#define MAX_PAYLOAD_SIZE 1024 // must be power of 2

#define MIN(a,b) (((a)<(b))?(a):(b))

#define bpf_read(src, dst)                            \
({                                                    \
    if (bpf_probe_read(&dst, sizeof(dst), src) < 0) { \
        return 0;                                     \
    }                                                 \
})

#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

struct trace_event_raw_sys_exit__stub {
	__u64 unused;
	__u64 unused2;
	long int ret;
};

// kernels 6.13+ give a program with 64 bytes of stack or more one stack per CPU, but a uprobe program runs preemptible
// and without a recursion check: on a preemptive kernel (the default since 7.0) a task that runs it on the CPU
// overwrites the stack of a task preempted in it. The verifier keeps a program with a tail call on the task's stack,
// and a tail call into this empty array returns at once
#if __KERNEL_FROM >= 512
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} uprobe_task_stack SEC(".maps");
#define USE_TASK_STACK(ctx) bpf_tail_call(ctx, &uprobe_task_stack, 0)
#else
#define USE_TASK_STACK(ctx)
#endif

#include "nodejs.c"
#include "python.c"
#include "proc.c"
#include "file.c"
#include "tcp/conntrack.c"
#include "tcp/state.c"
#include "tcp/retransmit.c"
#if __KERNEL_FROM >= 416
#include "l7/l7.c"
#include "l7/gotls.c"
#include "l7/openssl.c"
#include "l7/nodejs_tls.c"
#include "l7/rustls.c"
#include "l7/java_tls.c"
#else
#include "tcp/bytes.c"
#endif

char _license[] SEC("license") = "GPL";
