struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} rw_fd_by_pid_tgid SEC(".maps");

static inline __attribute__((__always_inline__))
int count_bytes_enter(struct trace_event_raw_args_with_fd__stub *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = args.fd;
    if (!bpf_map_lookup_elem(&active_connections, &cid)) {
        return 0;
    }
    bpf_map_update_elem(&rw_fd_by_pid_tgid, &id, &args.fd, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int count_bytes_exit(struct trace_event_raw_sys_exit__stub *ctx, __u8 is_write) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *fdp = bpf_map_lookup_elem(&rw_fd_by_pid_tgid, &id);
    if (!fdp) {
        return 0;
    }
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = *fdp;
    bpf_map_delete_elem(&rw_fd_by_pid_tgid, &id);
    long int ret = ctx->ret;
    if (ret <= 0) {
        return 0;
    }
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    if (is_write) {
        __sync_fetch_and_add(&conn->bytes_sent, ret);
    } else {
        __sync_fetch_and_add(&conn->bytes_received, ret);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int count_enter_write(void *ctx) { return count_bytes_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_writev")
int count_enter_writev(void *ctx) { return count_bytes_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_sendto")
int count_enter_sendto(void *ctx) { return count_bytes_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int count_enter_sendmsg(void *ctx) { return count_bytes_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_read")
int count_enter_read(void *ctx) { return count_bytes_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_readv")
int count_enter_readv(void *ctx) { return count_bytes_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int count_enter_recvfrom(void *ctx) { return count_bytes_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int count_enter_recvmsg(void *ctx) { return count_bytes_enter(ctx); }

SEC("tracepoint/syscalls/sys_exit_write")
int count_exit_write(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 1); }
SEC("tracepoint/syscalls/sys_exit_writev")
int count_exit_writev(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 1); }
SEC("tracepoint/syscalls/sys_exit_sendto")
int count_exit_sendto(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 1); }
SEC("tracepoint/syscalls/sys_exit_sendmsg")
int count_exit_sendmsg(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 1); }
SEC("tracepoint/syscalls/sys_exit_read")
int count_exit_read(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 0); }
SEC("tracepoint/syscalls/sys_exit_readv")
int count_exit_readv(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 0); }
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int count_exit_recvfrom(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 0); }
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int count_exit_recvmsg(struct trace_event_raw_sys_exit__stub *ctx) { return count_bytes_exit(ctx, 0); }
