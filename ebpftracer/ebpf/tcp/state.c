#define IPPROTO_TCP 6
#define MAX_CONNECTIONS 1000000

struct tcp_event {
    __u64 fd;
    __u64 timestamp;
    __u64 duration;
    __u32 type;
    __u32 pid;
    __u64 bytes_sent;
    __u64 bytes_received;
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
#if __KERNEL_FROM >= 506
    __u16 protocol;
#else
    __u8 protocol;
#endif
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} fd_by_pid_tgid SEC(".maps");

struct connection_id {
    __u64 fd;
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(void *));
    __uint(value_size, sizeof(struct connection_id));
    __uint(max_entries, MAX_CONNECTIONS);
} connection_id_by_socket SEC(".maps");

struct connection {
    __u64 timestamp;
    __u64 bytes_sent;
    __u64 bytes_received;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct connection_id));
    __uint(value_size, sizeof(struct connection));
    __uint(max_entries, MAX_CONNECTIONS);
} active_connections SEC(".maps");


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
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (args.oldstate == BPF_TCP_CLOSE && args.newstate == BPF_TCP_SYN_SENT) {
        __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);

        if (!fdp) {
            return 0;
        }
        struct connection_id cid = {};
        cid.pid = pid;
        cid.fd = *fdp;

        struct connection conn = {};
        conn.timestamp = bpf_ktime_get_ns();

        bpf_map_delete_elem(&fd_by_pid_tgid, &id);
        bpf_map_update_elem(&connection_id_by_socket, &args.skaddr, &cid, BPF_ANY);
        bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
        return 0;
    }

    __u64 fd = 0;
    __u32 type = 0;
    __u64 timestamp = 0;
    __u64 duration = 0;
    void *map = &tcp_connect_events;

    struct tcp_event e = {};

    if (args.oldstate == BPF_TCP_SYN_SENT) {
        struct connection_id *cid = bpf_map_lookup_elem(&connection_id_by_socket, &args.skaddr);
        if (!cid) {
            return 0;
        }
        struct connection *conn = bpf_map_lookup_elem(&active_connections, cid);
        if (!conn) {
            return 0;
        }
        if (args.newstate == BPF_TCP_ESTABLISHED) {
            timestamp = conn->timestamp;
            type = EVENT_TYPE_CONNECTION_OPEN;
        } else if (args.newstate == BPF_TCP_CLOSE) {
            bpf_map_delete_elem(&active_connections, cid);
            type = EVENT_TYPE_CONNECTION_ERROR;
        }
        duration = bpf_ktime_get_ns() - conn->timestamp;
        pid = cid->pid;
        fd = cid->fd;
    }
    if (args.oldstate == BPF_TCP_ESTABLISHED && (args.newstate == BPF_TCP_FIN_WAIT1 || args.newstate == BPF_TCP_CLOSE_WAIT)) {
        struct connection_id *cid = bpf_map_lookup_elem(&connection_id_by_socket, &args.skaddr);
        if (cid) {
            pid = cid->pid;
            fd = cid->fd;
            struct connection *conn = bpf_map_lookup_elem(&active_connections, cid);
            if (conn) {
                e.bytes_sent = conn->bytes_sent;
                e.bytes_received = conn->bytes_received;
                bpf_map_delete_elem(&active_connections, cid);
            }
            bpf_map_delete_elem(&connection_id_by_socket, &args.skaddr);
        }
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
    e.type = type;
    e.duration = duration;
    e.timestamp = timestamp;
    e.pid = pid;
    e.sport = args.sport;
    e.dport = args.dport;
    e.fd = fd;
    __builtin_memcpy(&e.saddr, &args.saddr_v6, sizeof(e.saddr));
    __builtin_memcpy(&e.daddr, &args.daddr_v6, sizeof(e.saddr));

    bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

struct trace_event_raw_args_with_fd__stub {
    __u64 unused;
    long int id;
    __u64 fd;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(void *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&fd_by_pid_tgid, &id, &args.fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(void *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&fd_by_pid_tgid, &id);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_exit_accept(struct trace_event_raw_sys_exit__stub* ctx) {
    if (ctx->ret < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = ctx->ret;
    bpf_map_delete_elem(&active_connections, &cid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit__stub* ctx) {
    return trace_exit_accept(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit__stub* ctx) {
    return trace_exit_accept(ctx);
}



