SEC("uprobe/openssl_SSL_write_enter")
int openssl_SSL_write_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.size = PT_REGS_PARM3(ctx);
    args.is_read = 0;
    bpf_map_update_elem(&ssl_pending, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/openssl_SSL_read_enter")
int openssl_SSL_read_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.is_read = 1;
    bpf_map_update_elem(&ssl_pending, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/openssl_SSL_read_ex_enter")
int openssl_SSL_read_ex_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.ret_ptr = (__u64 *)PT_REGS_PARM4(ctx);
    args.is_read = 1;
    bpf_map_update_elem(&ssl_pending, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/openssl_SSL_read_exit")
int openssl_SSL_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_pending, &pid_tgid);
    if (!args || !args->is_read || !args->fd) {
        bpf_map_delete_elem(&ssl_pending, &pid_tgid);
        return 0;
    }
    __u64 fd = args->fd;
    char *buf = args->buf;
    __u64 *ret_ptr = args->ret_ptr;
    bpf_map_delete_elem(&ssl_pending, &pid_tgid);

    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | IS_TLS_READ_ID;
    trace_enter_read(id, pid, fd, buf, ret_ptr, 0);

    int ret = (int)PT_REGS_RC(ctx);
    return trace_exit_read(ctx, id, pid, 1, ret);
}
