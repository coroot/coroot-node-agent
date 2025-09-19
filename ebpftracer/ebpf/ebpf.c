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

#include "nodejs.c"
#include "proc.c"
#include "file.c"
#include "tcp/conntrack.c"
#include "tcp/state.c"
#include "tcp/retransmit.c"
#include "l7/l7.c"
#include "l7/gotls.c"
#include "l7/openssl.c"
#include "python.c"

char _license[] SEC("license") = "GPL";
