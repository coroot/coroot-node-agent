#define IPPROTO_TCP 6

struct tcp_event {
	__u32 type;
	__u32 pid;
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} tcp_listen_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} tcp_connect_events SEC(".maps");

struct trace_event_raw_inet_sock_set_state__stub {
	__u64 unused;
	void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
#if __KERNEL >= 506
	__u16 protocol;
#else
	__u8 protocol;
#endif
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct sk_info {
	__u32 pid;
//	__u64 ts;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(void *));
	__uint(value_size, sizeof(struct sk_info));
	__uint(max_entries, 10240);
} sk_info SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx)
{
	struct trace_event_raw_inet_sock_set_state__stub args = {};
	if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
		return 0;
	}
	if (args.protocol != IPPROTO_TCP) {
		return 0;
	}
	if (args.oldstate == BPF_TCP_CLOSE && args.newstate == BPF_TCP_SYN_SENT) {
		struct sk_info i = {};
		i.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&sk_info, &args.skaddr, &i, BPF_ANY);
		return 0;
	}

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 type = 0;
	void *map = &tcp_connect_events;
	if (args.oldstate == BPF_TCP_SYN_SENT) {
		if (args.newstate == BPF_TCP_ESTABLISHED) {
			type = EVENT_TYPE_CONNECTION_OPEN;
		} else if (args.newstate == BPF_TCP_CLOSE) {
			type = EVENT_TYPE_CONNECTION_ERROR;
		} else {
			return 0;
		}
		struct sk_info *i = bpf_map_lookup_elem(&sk_info, &args.skaddr);
		if (!i) {
			return 0;
		}
		pid = i->pid;
		bpf_map_delete_elem(&sk_info, &args.skaddr);
	}
	if (args.oldstate == BPF_TCP_ESTABLISHED && (args.newstate == BPF_TCP_FIN_WAIT1 || args.newstate == BPF_TCP_CLOSE_WAIT)) {
		pid = 0;
		type = EVENT_TYPE_CONNECTION_CLOSE;
	}
	if (args.oldstate == BPF_TCP_CLOSE && args.newstate == BPF_TCP_LISTEN) {
		type = EVENT_TYPE_LISTEN_OPEN;
		map = &tcp_listen_events;
	}
	if (args.oldstate == BPF_TCP_LISTEN && args.newstate == BPF_TCP_CLOSE) {
		type = EVENT_TYPE_LISTEN_CLOSE;
		map = &tcp_listen_events;
	}

	if (type == 0) {
		return 0;
	}

	struct tcp_event e = {
		.type = type,
		.pid = pid,
		.sport = args.sport,
		.dport = args.dport,
	};
	__builtin_memcpy(&e.saddr, &args.saddr_v6, sizeof(e.saddr));
	__builtin_memcpy(&e.daddr, &args.daddr_v6, sizeof(e.saddr));

	bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}
