SEC("uprobe/rustls_write_enter")
int rustls_write_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    __u8 dummy = 1;
    bpf_map_update_elem(&rustls_pids, &pid, &dummy, BPF_ANY);

    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.size = PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&rustls_write_pending, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/rustls_read_enter")
int rustls_read_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    __u64 *fd_ptr = bpf_map_lookup_elem(&rustls_last_read_fd, &tid);
    if (!fd_ptr) {
        return 0;
    }
    __u64 fd = *fd_ptr;
    bpf_map_delete_elem(&rustls_last_read_fd, &tid);

    char *buf = (char *)PT_REGS_PARM2(ctx);
    __u64 id = tid | IS_TLS_READ_ID;
    return trace_enter_read(id, pid, fd, buf, 0, 0);
}

SEC("uprobe/rustls_read_exit")
int rustls_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 id = pid_tgid | IS_TLS_READ_ID;

    if (!RUSTLS_RET_IS_OK(ctx)) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    int ret = (int)RUSTLS_RET_SIZE(ctx);
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, id, pid, 1, ret);
}
