#include <asm-generic/fcntl.h>

struct file_event {
	__u32 type;
	__u32 pid;
	__u64 fd;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} file_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 10240);
} open_file_info SEC(".maps");

struct trace_event_raw_sys_enter__stub {
	__u64 unused;
	long int id;
	long unsigned int args[6];
};

struct trace_event_raw_sys_exit__stub {
	__u64 unused;
	long int id;
	long int ret;
};

static __always_inline
int trace_enter(struct trace_event_raw_sys_enter__stub* ctx, int at)
{
	int flags = (int)ctx->args[at+1];
	if (!(flags & O_ACCMODE & (O_WRONLY | O_RDWR))) {
		return 0;
	}
	char p[7];
	long res = bpf_probe_read_str(&p, sizeof(p), (void *)ctx->args[at]);
	if (p[0]=='/' && p[1]=='p' && p[2]=='r' && p[3]=='o' && p[4]=='c' && p[5]=='/') {
		return 0;
	}
	if (p[0]=='/' && p[1]=='d' && p[2]=='e' && p[3]=='v' && p[4]=='/') {
		return 0;
	}
	if (p[0]=='/' && p[1]=='s' && p[2]=='y' && p[3]=='s' && p[4]=='/') {
		return 0;
	}
	__u64 id = bpf_get_current_pid_tgid();
	__u32 v = 1;
	bpf_map_update_elem(&open_file_info, &id, &v, BPF_ANY);
	return 0;
}

static __always_inline
int trace_exit(struct trace_event_raw_sys_exit__stub* ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!bpf_map_lookup_elem(&open_file_info, &id)) {
		return 0;
	}
	bpf_map_delete_elem(&open_file_info, &id);
	if (ctx->ret < 0) {
		return 0;
	}
	struct file_event e = {
		.type = EVENT_TYPE_FILE_OPEN,
		.pid = id >> 32,
		.fd = ctx->ret,
	};
	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

#if defined(__TARGET_ARCH_x86)
SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct trace_event_raw_sys_enter__stub* ctx)
{
	return trace_enter(ctx, 0);
}

SEC("tracepoint/syscalls/sys_exit_open")
int sys_exit_open(struct trace_event_raw_sys_exit__stub* ctx)
{
	return trace_exit(ctx);
}
#endif

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct trace_event_raw_sys_enter__stub* ctx)
{
	return trace_enter(ctx, 1);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int sys_exit_openat(struct trace_event_raw_sys_exit__stub* ctx)
{
	return trace_exit(ctx);
}
