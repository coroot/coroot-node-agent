// Go internal ABI specification: https://go.dev/s/regabi
#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GOROUTINE(x) ((x)->r14)
#elif defined(__TARGET_ARCH_arm64)
#define GO_PARAM1(x) (((PT_REGS_ARM64 *)(x))->regs[0])
#define GO_PARAM2(x) (((PT_REGS_ARM64 *)(x))->regs[1])
#define GO_PARAM3(x) (((PT_REGS_ARM64 *)(x))->regs[2])
#define GOROUTINE(x) (((PT_REGS_ARM64 *)(x))->regs[28])
#endif

#define IS_TLS_READ_ID 0x8000000000000000

struct go_interface {
    __s64 type;
    void* ptr;
};

static inline __attribute__((__always_inline__))
int go_crypto_tls_get_fd_from_conn(struct pt_regs *ctx, __u32 *fd) {
    struct go_interface conn;
    if (bpf_probe_read(&conn, sizeof(conn), (void*)GO_PARAM1(ctx))) {
        return 1;
    };
    void* fd_ptr;
    if (bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn.ptr)) {
        return 1;
    }
    if (bpf_probe_read(fd, sizeof(*fd), fd_ptr + 0x10)) {
        return 1;
    }
    return 0;
}

SEC("uprobe/go_crypto_tls_write_enter")
int go_crypto_tls_write_enter(struct pt_regs *ctx) {
    __u32 fd;
    if (go_crypto_tls_get_fd_from_conn(ctx, &fd)) {
        return 0;
    }
    char *buf_ptr = (char*)GO_PARAM2(ctx);
    __u64 buf_size = GO_PARAM3(ctx);
    return trace_enter_write(ctx, fd, 1, buf_ptr, buf_size, 0);
}

SEC("uprobe/go_crypto_tls_read_enter")
int go_crypto_tls_read_enter(struct pt_regs *ctx) {
    __u32 fd;
    if (go_crypto_tls_get_fd_from_conn(ctx, &fd)) {
        return 0;
    }
    char *buf_ptr = (char*)GO_PARAM2(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 goroutine_id = GOROUTINE(ctx);
    __u64 pid = pid_tgid >> 32;
    __u64 id = pid << 32 | goroutine_id | IS_TLS_READ_ID;
    return trace_enter_read(id, fd, buf_ptr, 0, 0);
}

SEC("uprobe/go_crypto_tls_read_exit")
int go_crypto_tls_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u64 goroutine_id = GOROUTINE(ctx);
    __u64 id = pid << 32 | goroutine_id | IS_TLS_READ_ID;
    long int ret = GO_PARAM1(ctx);
    return trace_exit_read(ctx, id, pid, 1, ret);
}
