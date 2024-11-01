// TCP state monitoring, both client-side and server-side

#define IPPROTO_TCP 6
#define MAX_CONNECTIONS 1000000  // 可观测的最大连接数

// common structs
struct connection_id {
    __u64 fd;
    __u32 pid;
};

struct connection {  // TCP connection context
    __u64 timestamp;  // timestamp when client initialized this connection
    __u64 bytes_sent;
    __u64 bytes_received;
};

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
    __u8 saddr[16];  // IP address parser supports "IPv4 in IPv6".
    __u8 daddr[16];
} __attribute__((packed));

// arguments limited to `/sys/kernel/tracing/events/sock/inet_sock_set_state/format`
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

// arguments like `/sys/kernel/tracing/events/syscalls/sys_enter_connect/format`
struct trace_event_raw_args_with_fd__stub {
    __u64 unused;
    long int id;
    __u64 fd;
};


// ===== client-side =====
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));  // pointer to `struct tcp_event`
} tcp_connect_events SEC(".maps");  // `connect` belongs to client-side

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, struct tcp_event);
    __uint(max_entries, 1);
} tcp_connect_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct connection_id));
    __uint(value_size, sizeof(struct connection));
    __uint(max_entries, MAX_CONNECTIONS);
} active_connections SEC(".maps");  // active connections viewed from client-side pid and fd

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} fd_by_pid_tgid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(void *));
    __uint(value_size, sizeof(struct connection_id));
    __uint(max_entries, MAX_CONNECTIONS);
} connection_id_by_socket SEC(".maps");

// returns 1 iff client-side event happened .
int trace_cs_inet_sock_set_state(__u64 id, __u32 pid, struct trace_event_raw_inet_sock_set_state__stub *args) {
    if (!args) return 0;

    void *args_skaddr = args->skaddr;

    // 新建活跃连接（client-side active open）
    if (args->oldstate == BPF_TCP_CLOSE && args->newstate == BPF_TCP_SYN_SENT) {
        // 已经在 `sys_enter_connect` 插入。
        __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);
        if (!fdp) {
            return 0;
        }
        bpf_map_delete_elem(&fd_by_pid_tgid, &id);

        struct connection_id cid = {};
        cid.pid = pid;
        cid.fd = *fdp;

        struct connection conn = {};
        conn.timestamp = bpf_ktime_get_ns();

        bpf_map_update_elem(&connection_id_by_socket, &args_skaddr, &cid, BPF_ANY);
        bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
        return 0;
    }

    // 以下有关事件
    __u32 type = EVENT_TYPE_UNKNOWN;
    __u64 fd = 0;
    __u64 timestamp = 0;
    __u64 duration = 0;

    // 客户端发出 SYN 之后
    if (args->oldstate == BPF_TCP_SYN_SENT) {
        struct connection_id *cid = bpf_map_lookup_elem(&connection_id_by_socket, &args_skaddr);
        if (!cid) {
            return 0;
        }
        // 从缓存表中拿到活跃连接
        struct connection *conn = bpf_map_lookup_elem(&active_connections, cid);
        if (!conn) {
            return 0;
        }
        // 连接打开
        if (args->newstate == BPF_TCP_ESTABLISHED) {
            timestamp = conn->timestamp;
            type = EVENT_TYPE_CONNECTION_OPEN;
        }
        // 建连过程异常，清除活跃连接
        else if (args->newstate == BPF_TCP_CLOSE) {
            bpf_map_delete_elem(&active_connections, cid);
            type = EVENT_TYPE_CONNECTION_ERROR;
        }
        duration = bpf_ktime_get_ns() - conn->timestamp;
        pid = cid->pid;
        fd = cid->fd;
    }

    // 客户端准备主动关闭连接，清除活跃连接的套接字，但不清理活跃连接
    if (args->oldstate == BPF_TCP_ESTABLISHED && args->newstate == BPF_TCP_FIN_WAIT1) {
        bpf_map_delete_elem(&connection_id_by_socket, &args_skaddr);
    }

    // 构建 connect_event
    if (type == EVENT_TYPE_UNKNOWN) {
        return 0;
    }

    int zero = 0;
    struct tcp_event *connect_event = bpf_map_lookup_elem(&tcp_connect_event_heap, &zero);
    if (!connect_event) {
        return 0;
    }

    connect_event->type = type;
    connect_event->fd = fd;
    connect_event->timestamp = timestamp;
    connect_event->duration = duration;
    connect_event->pid = pid;
    connect_event->sport = args->sport;
    connect_event->dport = args->dport;
    __builtin_memcpy(&connect_event->saddr, &args->saddr_v6, 16);
    __builtin_memcpy(&connect_event->daddr, &args->daddr_v6, 16);

    return 1;
}

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
int sys_exit_connect(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);
    if (!fdp) {
        return 0;
    }
    bpf_map_delete_elem(&fd_by_pid_tgid, &id);

    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = *fdp;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn && ctx->ret == 0) {  // non-TCP connection
        // In this way we update active_connections, since can't hook `set_state`.
        struct connection conn = {};
        conn.timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(void *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = args.fd;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (conn) {  // non-TCP connection
        struct tcp_event e = {};
        e.type = EVENT_TYPE_CONNECTION_CLOSE;
        e.pid = cid.pid;
        e.fd = cid.fd;
        e.bytes_sent = conn->bytes_sent;
        e.bytes_received = conn->bytes_received;
        e.timestamp = conn->timestamp;
        bpf_perf_event_output(ctx, &tcp_connect_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
        bpf_map_delete_elem(&active_connections, &cid);
    }
    return 0;
}

// ===== server-side =====
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));  // pointer to `struct tcp_event`
} tcp_listen_events SEC(".maps");  // `listen` belongs to server-side

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, struct tcp_event);
    __uint(max_entries, 1);
} tcp_listen_event_heap SEC(".maps");

struct connection_ss {  // TCP connection context viewed from server-side
    __u64 timestamp;  // timestamp when server initialized this connection
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct connection_id));
    __uint(value_size, sizeof(struct connection_ss));
    __uint(max_entries, MAX_CONNECTIONS);
} active_connections_ss SEC(".maps");  // active connections viewed from server-side pid and fd

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} fd_by_pid_tgid_ss SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(void *));
    __uint(value_size, sizeof(struct connection_id));
    __uint(max_entries, MAX_CONNECTIONS);
} connection_id_by_socket_ss SEC(".maps");


// returns 1 iff server-side event happened .
int trace_ss_inet_sock_set_state(__u64 id, __u32 pid, struct trace_event_raw_inet_sock_set_state__stub *args) {
    if (!args) return 0;

    void *args_skaddr = args->skaddr;

    // 新建活跃连接（server-side passive open）
    if (args->oldstate == BPF_TCP_CLOSE && args->newstate == BPF_TCP_LISTEN) {
        // 已经在 `sys_enter_listen` 插入。
        __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid_ss, &id);
        if (!fdp) {
            return 0;
        }
        bpf_map_delete_elem(&fd_by_pid_tgid_ss, &id);

        struct connection_id cid = {};
        cid.pid = pid;
        cid.fd = *fdp;

        struct connection_ss conn = {};
        conn.timestamp = bpf_ktime_get_ns();

        bpf_map_update_elem(&connection_id_by_socket_ss, &args_skaddr, &cid, BPF_ANY);
        bpf_map_update_elem(&active_connections_ss, &cid, &conn, BPF_ANY);
        return 0;
    }

    // 以下有关事件
    __u32 type = EVENT_TYPE_UNKNOWN;
    __u64 fd = 0;
    __u64 timestamp = 0;
    __u64 duration = 0;

    // 服务端接收 SYN 之后
    if (args->oldstate == BPF_TCP_SYN_RECV) {
        struct connection_id *cid = bpf_map_lookup_elem(&connection_id_by_socket_ss, &args_skaddr);
        if (!cid) {
            // fixme 此处会频繁退出，原因未知。
            return 0;
        }
        // 从缓存表中拿到活跃连接，正常应该都能拿到
        struct connection *conn = bpf_map_lookup_elem(&active_connections_ss, cid);
        if (!conn) {
            return 0;
        }
        // 连接正常打开
        if (args->newstate == BPF_TCP_ESTABLISHED) {
            timestamp = conn->timestamp;
        }
        // 建连过程异常（timeout），清除活跃连接
        else if (args->newstate == BPF_TCP_CLOSE) {
            bpf_map_delete_elem(&active_connections_ss, cid);
        }
        // 正常退出（FIN），清除活跃连接
        else if (args->newstate == BPF_TCP_FIN_WAIT1) {
            bpf_map_delete_elem(&active_connections_ss, cid);
        }
        duration = bpf_ktime_get_ns() - conn->timestamp;
        pid = cid->pid;
        fd = cid->fd;
    }

    // 连接准备被动关闭
    if (args->oldstate == BPF_TCP_ESTABLISHED && args->newstate == BPF_TCP_CLOSE_WAIT) {
        bpf_map_delete_elem(&connection_id_by_socket_ss, &args_skaddr);
        // 事件类型：服务端正常关闭。
    }

    if (args->oldstate == BPF_TCP_CLOSE && args->newstate == BPF_TCP_LISTEN) {
        type = EVENT_TYPE_LISTEN_OPEN;
    }

    if (args->oldstate == BPF_TCP_LISTEN && args->newstate == BPF_TCP_CLOSE) {
        type = EVENT_TYPE_LISTEN_CLOSE;
    }

    if (type == EVENT_TYPE_UNKNOWN) {
        return 0;
    }

    int zero = 0;
    struct tcp_event *listen_event = bpf_map_lookup_elem(&tcp_listen_event_heap, &zero);
    if (!listen_event) {
        return 0;
    }

    listen_event->type = type;
    listen_event->fd = fd;
    listen_event->timestamp = timestamp;
    listen_event->duration = duration;
    listen_event->pid = pid;
    listen_event->sport = args->sport;
    listen_event->dport = args->dport;
    __builtin_memcpy(&listen_event->saddr, &args->saddr_v6, 16);
    __builtin_memcpy(&listen_event->daddr, &args->daddr_v6, 16);

    return 1;
}


SEC("tracepoint/syscalls/sys_enter_listen")
int sys_enter_listen(void *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&fd_by_pid_tgid_ss, &id, &args.fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int sys_exit_listen(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid_ss, &id);
    if (!fdp) {
        return 0;
    }
    bpf_map_delete_elem(&fd_by_pid_tgid_ss, &id);
    return 0;
}


// ===== both client-side and server-side =====
SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx) {
    struct trace_event_raw_inet_sock_set_state__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    if (args.protocol != IPPROTO_TCP) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    int zero = 0;

    int is_client_side = trace_cs_inet_sock_set_state(id, pid, &args);
    if (is_client_side) {
        struct tcp_event *connect_event = bpf_map_lookup_elem(&tcp_connect_event_heap, &zero);
        if (!connect_event || connect_event == EVENT_TYPE_UNKNOWN) {
            return 0;
        }
        bpf_perf_event_output(ctx, &tcp_connect_events, BPF_F_CURRENT_CPU, connect_event, sizeof(struct tcp_event));
        return 0;
    }

    // fixme 如何避免在 server-side 逻辑中引入不必要的 client-side 逻辑，因为 trace_cs 有副作用。
    int is_server_side = trace_ss_inet_sock_set_state(id, pid, &args);
    if (is_server_side) {
        struct tcp_event *listen_event = bpf_map_lookup_elem(&tcp_listen_event_heap, &zero);
        if (!listen_event || listen_event == EVENT_TYPE_UNKNOWN) {
            return 0;
        }
        bpf_perf_event_output(ctx, &tcp_listen_events, BPF_F_CURRENT_CPU, listen_event, sizeof(struct tcp_event));
        return 0;
    }

    return 0;
}
