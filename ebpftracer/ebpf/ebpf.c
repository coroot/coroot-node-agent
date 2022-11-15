#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define EVENT_TYPE_PROCESS_START	1
#define EVENT_TYPE_PROCESS_EXIT		2
#define EVENT_TYPE_CONNECTION_OPEN	3
#define EVENT_TYPE_CONNECTION_CLOSE	4
#define EVENT_TYPE_CONNECTION_ERROR	5
#define EVENT_TYPE_LISTEN_OPEN		6
#define EVENT_TYPE_LISTEN_CLOSE 	7
#define EVENT_TYPE_FILE_OPEN		8
#define EVENT_TYPE_TCP_RETRANSMIT	9

#define EVENT_REASON_OOM_KILL		1

#include "proc.c"
#include "file.c"
#include "tcp/state.c"
#include "tcp/retransmit.c"
#include "l7/l7.c"

char _license[] SEC("license") = "GPL";
