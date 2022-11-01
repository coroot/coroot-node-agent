struct rw_args_t {
    __u64 fd;
    const char* buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct rw_args_t));
	__uint(max_entries, 10240);
} active_reads SEC(".maps");

struct socket_key {
    __u64 fd;
    __u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct socket_key));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 10240);
} active_http_requests SEC(".maps");

struct trace_event_raw_sys_enter_rw__stub {
	__u64 unused;
	long int id;
	__u64 fd;
	const char* buf;
};

struct trace_event_raw_sys_exit_rw__stub {
	__u64 unused;
	long int id;
	long int ret;
};

struct http_event {
	__u64 fd;
	__u32 pid;
    __u32 status;
    __u64 duration;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} http_events SEC(".maps");


static __always_inline
int is_http_request(char b[16]) {
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T') {
        return 1;
    }
    if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T') {
        return 1;
    }
    if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E') {
        return 1;
    }
    if (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T') {
        return 1;
    }
    if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H') {
        return 1;
    }
    return 0;
}
static __always_inline
__u32 parse_http_status(char b[16]) {
    if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/') {
        return 0;
    }
    if (b[5] < '0' || b[5] > '9') {
        return 0;
    }
    if (b[6] != '.') {
        return 0;
    }
    if (b[7] < '0' || b[7] > '9') {
        return 0;
    }
    if (b[8] != ' ') {
        return 0;
    }
    if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
        return 0;
    }
    return (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
}

static inline __attribute__((__always_inline__))
int trace_http_request(__u64 fd, void *buf) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char p[16];
    long ret = bpf_probe_read_str(&p, sizeof(p), buf);
    if (ret < 16) {
        return 0;
    }
    if (!is_http_request(p)) {
        return 0;
    }
    struct socket_key k = {};
    k.pid = pid;
    k.fd = fd;
    __u64 ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&active_http_requests, &k, &ns, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct rw_args_t args = {};
    args.fd = ctx->fd;
    args.buf = ctx->buf;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_exit_read(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct rw_args_t *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }
    bpf_map_delete_elem(&active_reads, &id);
    if (ctx->ret <= 0) {
        return 0;
    }
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = args->fd;
    __u64 *req_start = bpf_map_lookup_elem(&active_http_requests, &k);
    if (!req_start) {
        return 0;
    }
    bpf_map_delete_elem(&active_http_requests, &k);
    char p[16];
    long ret = bpf_probe_read_str(&p, sizeof(p), (void *)args->buf);
    if (ret < 16) {
        return 0;
    }
    __u32 status = parse_http_status(p);

    if (status <= 0) {
        return 0;
    }
    struct http_event e = {};
    e.fd = k.fd;
    e.pid = k.pid;
    e.status = status;
    e.duration = bpf_ktime_get_ns() - *req_start;
    bpf_perf_event_output(ctx, &http_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    void *vec;
    if (bpf_probe_read(&vec, sizeof(void*), (void *)ctx->buf) < 0) {
        return 0;
    }
    return trace_http_request(ctx->fd, vec);
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_http_request(ctx->fd, (void *)ctx->buf);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_http_request(ctx->fd, (void *)ctx->buf);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_read(ctx);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    void *vec;
    if (bpf_probe_read(&vec, sizeof(void*), (void *)ctx->buf) < 0) {
        return 0;
    }
    struct rw_args_t args = {};
    args.fd = ctx->fd;
    args.buf = vec;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_read(ctx);
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    return trace_exit_read(ctx);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int sys_exit_readv(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    return trace_exit_read(ctx);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    return trace_exit_read(ctx);
}
