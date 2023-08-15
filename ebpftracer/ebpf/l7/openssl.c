struct unused {};
typedef long (*unused_fn)();

struct bio_st {
    struct unused* method;
    unused_fn callback;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

struct bio_st_v1_1_1 {
    struct unused* method;
    unused_fn callback;
    unused_fn callback_ex; // new field
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

struct bio_st_v3_0 {
    struct unused* context; // new field
    struct unused* method;
    unused_fn callback;
    unused_fn callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

struct ssl_st {
    __s32 version;
    struct unused* method;
    struct bio_st* rbio;  // used by SSL_read
    struct bio_st* wbio;  // used by SSL_write
};

#define GET_FD(ctx, bio_t, bio_rw)                                      \
({                                                                      \
    struct ssl_st ssl;                                                  \
    if (bpf_probe_read(&ssl, sizeof(ssl), (void*)PT_REGS_PARM1(ctx))) { \
        return 0;                                                       \
    };                                                                  \
    struct bio_t bio;                                                   \
    if (bpf_probe_read(&bio, sizeof(bio), (void*)ssl.bio_rw)) {         \
        return 0;                                                       \
    };                                                                  \
    __u32 fd = bio.num;                                                 \
    if (fd <= 2) {                                                      \
        return 0;                                                       \
    }                                                                   \
    fd;                                                                 \
})

#define WRITE_ENTER(ctx, bio_t)                              \
({                                                           \
    __u32 fd = GET_FD(ctx, bio_t, wbio);                     \
    char* buf_ptr = (char*)PT_REGS_PARM2(ctx);               \
    __u64 buf_size = PT_REGS_PARM3(ctx);                     \
    return trace_enter_write(ctx, fd, 1, buf_ptr, buf_size); \
})

#define READ_ENTER(ctx, bio_t)                   \
({                                               \
    __u32 fd = GET_FD(ctx, bio_t, rbio);         \
    char* buf_ptr = (char*)PT_REGS_PARM2(ctx);   \
    __u64 pid_tgid = bpf_get_current_pid_tgid(); \
    __u64 id = pid_tgid | IS_TLS_READ_ID;        \
    return trace_enter_read(id, fd, buf_ptr, 0); \
})

#define READ_EX_ENTER(ctx, bio_t)                      \
({                                                     \
    __u32 fd = GET_FD(ctx, bio_t, rbio);               \
    char* buf_ptr = (char*)PT_REGS_PARM2(ctx);         \
    __u64 pid_tgid = bpf_get_current_pid_tgid();       \
    __u64 id = pid_tgid | IS_TLS_READ_ID;              \
    __u64* ret_ptr = (__u64*)PT_REGS_PARM4(ctx);       \
    return trace_enter_read(id, fd, buf_ptr, ret_ptr); \
})

SEC("uprobe/openssl_SSL_write_enter")
int openssl_SSL_write_enter(struct pt_regs *ctx) {
    WRITE_ENTER(ctx, bio_st);
}

SEC("uprobe/openssl_SSL_write_enter_v1_1_1")
int openssl_SSL_write_enter_v1_1_1(struct pt_regs *ctx) {
    WRITE_ENTER(ctx, bio_st_v1_1_1);
}

SEC("uprobe/openssl_SSL_write_enter_v3_0")
int openssl_SSL_write_enter_v3_0(struct pt_regs *ctx) {
    WRITE_ENTER(ctx, bio_st_v3_0);
}

SEC("uprobe/openssl_SSL_read_enter")
int openssl_SSL_read_enter(struct pt_regs *ctx) {
    READ_ENTER(ctx, bio_st);
}

SEC("uprobe/openssl_SSL_read_ex_enter")
int openssl_SSL_read_ex_enter(struct pt_regs *ctx) {
    READ_EX_ENTER(ctx, bio_st);
}

SEC("uprobe/openssl_SSL_read_enter_v1_1_1")
int openssl_SSL_read_enter_v1_1_1(struct pt_regs *ctx) {
    READ_ENTER(ctx, bio_st_v1_1_1);
}

SEC("uprobe/openssl_SSL_read_ex_enter_v1_1_1")
int openssl_SSL_read_ex_enter_v1_1_1(struct pt_regs *ctx) {
    READ_EX_ENTER(ctx, bio_st_v1_1_1);
}

SEC("uprobe/openssl_SSL_read_enter_v3_0")
int openssl_SSL_read_enter_v3_0(struct pt_regs *ctx) {
    READ_ENTER(ctx, bio_st_v3_0);
}

SEC("uprobe/openssl_SSL_read_ex_enter_v3_0")
int openssl_SSL_read_ex_enter_v3_0(struct pt_regs *ctx) {
    READ_EX_ENTER(ctx, bio_st_v3_0);
}

SEC("uprobe/openssl_SSL_read_exit")
int openssl_SSL_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | IS_TLS_READ_ID;
    int ret = (int)PT_REGS_RC(ctx);
    return trace_exit_read(ctx, id, pid, 1, ret);
}
