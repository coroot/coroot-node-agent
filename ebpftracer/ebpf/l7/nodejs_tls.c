struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, struct nodejs_pending_write);
    __uint(max_entries, 1);
} nodejs_tls_write_scratch SEC(".maps");

struct nodejs_tls_wrap_key {
    __u64 wrap;
    __u32 pid;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct nodejs_tls_wrap_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 65536);
} nodejs_tls_wrap_ssl SEC(".maps");

// containers of one image share the binary's inode, so the probes can fire more than once per call: keep them idempotent
SEC("uprobe/nodejs_tls_on_uv_read_enter")
int nodejs_tls_on_uv_read_enter(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_tls_enc_out_ssl, &tid);
    __u64 *last_fd = bpf_map_lookup_elem(&nodejs_tls_last_read_fd, &tid);
    if (!last_fd) {
        bpf_map_delete_elem(&nodejs_tls_stream_read_fd, &tid);
        return 0;
    }
    __u64 fd = *last_fd; // libuv reads the socket right before it calls the read callback
    bpf_map_update_elem(&nodejs_tls_stream_read_fd, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_on_uv_read_exit")
int nodejs_tls_on_uv_read_exit(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_tls_stream_read_fd, &tid);
    bpf_map_delete_elem(&nodejs_tls_last_read_fd, &tid);
    return 0;
}

// TLSWrap::InitSSL stores the TLSWrap as the SSL's app data (ex_data index 0)
SEC("uprobe/nodejs_tls_SSL_set_ex_data")
int nodejs_tls_SSL_set_ex_data(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    if (PT_REGS_PARM2(ctx) != 0 || !bpf_map_lookup_elem(&nodejs_tls_pids, &pid)) {
        return 0;
    }
    struct nodejs_tls_wrap_key k = {};
    k.wrap = PT_REGS_PARM3(ctx);
    k.pid = pid;
    __u64 ssl = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&nodejs_tls_wrap_ssl, &k, &ssl, BPF_ANY);
    return 0;
}

// EncOut can leave through a tail call, which the exit probe misses: the SSL_* and OnUvRead probes also end the EncOut scope
SEC("uprobe/nodejs_tls_enc_out_enter")
int nodejs_tls_enc_out_enter(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    if (!bpf_map_lookup_elem(&nodejs_tls_pids, &pid)) {
        return 0;
    }
    struct nodejs_tls_wrap_key k = {};
    k.wrap = PT_REGS_PARM1(ctx);
    k.pid = pid;
    __u64 *ssl = bpf_map_lookup_elem(&nodejs_tls_wrap_ssl, &k);
    if (!ssl) {
        bpf_map_delete_elem(&nodejs_tls_enc_out_ssl, &tid);
        return 0;
    }
    __u64 enc_out_ssl = *ssl;
    bpf_map_update_elem(&nodejs_tls_enc_out_ssl, &tid, &enc_out_ssl, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_enc_out_exit")
int nodejs_tls_enc_out_exit(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_tls_enc_out_ssl, &tid);
    bpf_map_delete_elem(&nodejs_tls_write_pending, &tid);
    return 0;
}

SEC("uprobe/nodejs_tls_SSL_write_enter")
int nodejs_tls_SSL_write_enter(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_tls_enc_out_ssl, &tid);
    __u32 pid = tid >> 32;
    if (!bpf_map_lookup_elem(&nodejs_tls_pids, &pid)) {
        return 0;
    }
    struct nodejs_ssl_args args = {};
    args.ssl = PT_REGS_PARM1(ctx);
    args.buf = (char *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&nodejs_tls_active_write, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_SSL_write_ex_enter")
int nodejs_tls_SSL_write_ex_enter(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_tls_enc_out_ssl, &tid);
    __u32 pid = tid >> 32;
    if (!bpf_map_lookup_elem(&nodejs_tls_pids, &pid)) {
        return 0;
    }
    __u64 *ret_ptr = (__u64 *)PT_REGS_PARM4(ctx);
    if (!ret_ptr) {
        return 0;
    }
    struct nodejs_ssl_args args = {};
    args.ssl = PT_REGS_PARM1(ctx);
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.ret_ptr = ret_ptr;
    bpf_map_update_elem(&nodejs_tls_active_write, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_SSL_write_exit")
int nodejs_tls_SSL_write_exit(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    struct nodejs_ssl_args *args = bpf_map_lookup_elem(&nodejs_tls_active_write, &tid);
    if (!args) {
        return 0;
    }
    __u64 ssl = args->ssl;
    char *buf = args->buf;
    __u64 *ret_ptr = args->ret_ptr;
    bpf_map_delete_elem(&nodejs_tls_active_write, &tid);

    long int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }
    if (ret_ptr) {
        if (bpf_probe_read(&ret, sizeof(ret), (void *)ret_ptr)) {
            return 0;
        }
        if (ret <= 0) {
            return 0;
        }
    }

    __u32 pid = tid >> 32;
    struct nodejs_ssl_key sk = {};
    sk.ssl = ssl;
    sk.pid = pid;
    __u64 *fd_ptr = bpf_map_lookup_elem(&nodejs_tls_ssl_fd, &sk);
    if (fd_ptr) {
        return trace_enter_write(ctx, *fd_ptr, 1, 1, buf, ret, 0);
    }

    struct nodejs_pending_write *existing = bpf_map_lookup_elem(&nodejs_tls_write_pending, &tid);
    if (existing && existing->ssl == ssl) {
        return 0;
    }

    int zero = 0;
    struct nodejs_pending_write *pw = bpf_map_lookup_elem(&nodejs_tls_write_scratch, &zero);
    if (!pw) {
        return 0;
    }
    pw->ssl = ssl;
    pw->size = ret;
    __u64 copy_size = ret;
    TRUNCATE_PAYLOAD_SIZE(copy_size);
    if (copy_size == 0 || bpf_probe_read(pw->payload, copy_size, buf)) {
        return 0;
    }
    bpf_map_update_elem(&nodejs_tls_write_pending, &tid, pw, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_SSL_read_enter")
int nodejs_tls_SSL_read_enter(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_tls_enc_out_ssl, &tid);
    __u32 pid = tid >> 32;
    if (!bpf_map_lookup_elem(&nodejs_tls_pids, &pid)) {
        return 0;
    }
    struct nodejs_ssl_args args = {};
    args.ssl = PT_REGS_PARM1(ctx);
    args.buf = (char *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&nodejs_tls_active_read, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_SSL_read_ex_enter")
int nodejs_tls_SSL_read_ex_enter(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_tls_enc_out_ssl, &tid);
    __u32 pid = tid >> 32;
    if (!bpf_map_lookup_elem(&nodejs_tls_pids, &pid)) {
        return 0;
    }
    __u64 *ret_ptr = (__u64 *)PT_REGS_PARM4(ctx);
    if (!ret_ptr) {
        return 0;
    }
    struct nodejs_ssl_args args = {};
    args.ssl = PT_REGS_PARM1(ctx);
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.ret_ptr = ret_ptr;
    bpf_map_update_elem(&nodejs_tls_active_read, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_SSL_read_exit")
int nodejs_tls_SSL_read_exit(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    struct nodejs_ssl_args *args = bpf_map_lookup_elem(&nodejs_tls_active_read, &tid);
    if (!args) {
        return 0;
    }
    __u64 ssl = args->ssl;
    char *buf = args->buf;
    __u64 *ret_ptr = args->ret_ptr;
    bpf_map_delete_elem(&nodejs_tls_active_read, &tid);

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    __u32 pid = tid >> 32;
    struct nodejs_ssl_key sk = {};
    sk.ssl = ssl;
    sk.pid = pid;
    __u64 fd = 0;
    __u64 *fd_ptr = bpf_map_lookup_elem(&nodejs_tls_ssl_fd, &sk);
    if (fd_ptr) {
        fd = *fd_ptr;
    } else {
        __u64 *rfd = bpf_map_lookup_elem(&nodejs_tls_stream_read_fd, &tid);
        if (!rfd) {
            return 0;
        }
        fd = *rfd;
        bpf_map_update_elem(&nodejs_tls_ssl_fd, &sk, &fd, BPF_NOEXIST);
    }
    bpf_map_delete_elem(&nodejs_tls_stream_read_fd, &tid);

    __u64 id = tid | IS_TLS_READ_ID;
    trace_enter_read(id, pid, fd, 1, buf, ret_ptr, 0);
    return trace_exit_read(ctx, id, pid, 1, ret);
}

SEC("uprobe/nodejs_tls_SSL_free")
int nodejs_tls_SSL_free(struct pt_regs *ctx) {
    USE_TASK_STACK(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    if (!bpf_map_lookup_elem(&nodejs_tls_pids, &pid)) {
        return 0;
    }
    struct nodejs_ssl_key sk = {};
    sk.ssl = PT_REGS_PARM1(ctx);
    sk.pid = pid;
    bpf_map_delete_elem(&nodejs_tls_ssl_fd, &sk);
    return 0;
}
