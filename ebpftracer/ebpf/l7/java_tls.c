SEC("uprobe/java_tls_write_enter")
int java_tls_write_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    __u8 dummy = 1;
    bpf_map_update_elem(&java_tls_pids, &pid, &dummy, BPF_ANY);

    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM1(ctx);
    args.size = PT_REGS_PARM2(ctx);
    args.is_read = 0;
    bpf_map_update_elem(&ssl_pending, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/java_tls_read_exit")
int java_tls_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct java_tls_read *r = bpf_map_lookup_elem(&java_tls_last_read, &pid_tgid);
    if (!r) {
        return 0;
    }
    __u64 fd = r->fd;
    bpf_map_delete_elem(&java_tls_last_read, &pid_tgid);

    char *buf = (char *)PT_REGS_PARM1(ctx);
    __s64 size = (__s64)PT_REGS_PARM2(ctx);

    if (size <= 0) {
        return 0;
    }

    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | IS_TLS_READ_ID;
    trace_enter_read(id, pid, fd, 1, buf, 0, 0);
    return trace_exit_read(ctx, id, pid, 1, size);
}

struct java_tls_engine_io {
    __u64 engine;
    __u64 record_tag;
    char *buf;
    __s64 size;
};

struct java_tls_engine_id {
    __u32 pid;
    __u32 engine;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct java_tls_engine_id));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 32768);
} java_tls_engine_fds SEC(".maps");

static __always_inline
void java_tls_track_pid(__u32 pid) {
    __u8 dummy = 1;
    bpf_map_update_elem(&java_tls_pids, &pid, &dummy, BPF_ANY);
}

SEC("uprobe/java_tls_engine_read")
int java_tls_engine_read(struct pt_regs *ctx) {
    struct java_tls_engine_io io;
    if (bpf_probe_read(&io, sizeof(io), (void *)PT_REGS_PARM1(ctx))) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct java_tls_engine_id engine = {.pid = pid, .engine = io.engine};
    struct java_tls_record record = {.pid = pid, .tag = io.record_tag};

    __u64 fd;
    __u64 *fd_ptr = bpf_map_lookup_elem(&java_tls_engine_fds, &engine);
    __u64 *record_fd_ptr = io.record_tag ? bpf_map_lookup_elem(&java_tls_record_fds, &record) : 0;
    if (record_fd_ptr) {
        fd = *record_fd_ptr;
        bpf_map_delete_elem(&java_tls_record_fds, &record);
        if (!fd_ptr || *fd_ptr != fd) {
            bpf_map_update_elem(&java_tls_engine_fds, &engine, &fd, BPF_ANY);
        }
    } else if (fd_ptr) {
        fd = *fd_ptr;
    } else {
        java_tls_track_pid(pid);
        return 0;
    }
    if (io.size <= 0) {
        return 0;
    }

    __u64 id = pid_tgid | IS_TLS_READ_ID;
    trace_enter_read(id, pid, fd, 1, io.buf, 0, 0);
    return trace_exit_read(ctx, id, pid, 1, io.size);
}

SEC("uprobe/java_tls_engine_write")
int java_tls_engine_write(struct pt_regs *ctx) {
    struct java_tls_engine_io io;
    if (bpf_probe_read(&io, sizeof(io), (void *)PT_REGS_PARM1(ctx))) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct java_tls_engine_id engine = {.pid = pid_tgid >> 32, .engine = io.engine};

    __u64 *fd_ptr = bpf_map_lookup_elem(&java_tls_engine_fds, &engine);
    if (!fd_ptr) {
        java_tls_track_pid(engine.pid);
        return 0;
    }
    if (io.size <= 0) {
        return 0;
    }
    return trace_enter_write(ctx, *fd_ptr, 1, 1, io.buf, io.size, 0);
}
