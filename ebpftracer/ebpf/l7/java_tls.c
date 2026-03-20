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

    __u64 *fd_ptr = bpf_map_lookup_elem(&java_tls_last_read_fd, &pid_tgid);
    if (!fd_ptr) {
        return 0;
    }
    __u64 fd = *fd_ptr;
    bpf_map_delete_elem(&java_tls_last_read_fd, &pid_tgid);

    char *buf = (char *)PT_REGS_PARM1(ctx);
    __s64 size = (__s64)PT_REGS_PARM2(ctx);

    if (size <= 0) {
        return 0;
    }

    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | IS_TLS_READ_ID;
    trace_enter_read(id, pid, fd, buf, 0, 0);
    return trace_exit_read(ctx, id, pid, 1, size);
}
