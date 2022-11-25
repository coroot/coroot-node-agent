#include "http.c"
#include "postgres.c"
#include "redis.c"
#include "memcached.c"
#include "mysql.c"
#include "mongo.c"

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_HTTP	    1
#define PROTOCOL_POSTGRES	2
#define PROTOCOL_REDIS	    3
#define PROTOCOL_MEMCACHED  4
#define PROTOCOL_MYSQL      5
#define PROTOCOL_MONGO      6

struct l7_event {
    __u64 fd;
    __u64 connection_timestamp;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

struct rw_args_t {
    __u64 fd;
    char* buf;
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

struct l7_request {
    __u64 ns;
    __u8 protocol;
    __u8 partial;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct socket_key));
    __uint(value_size, sizeof(struct l7_request));
    __uint(max_entries, 32768);
} active_l7_requests SEC(".maps");

struct trace_event_raw_sys_enter_rw__stub {
    __u64 unused;
    long int id;
    __u64 fd;
    char* buf;
    __u64 size;
};

struct trace_event_raw_sys_exit_rw__stub {
    __u64 unused;
    long int id;
    long int ret;
};

struct iov {
    char* buf;
    __u64 size;
};

static inline __attribute__((__always_inline__))
int trace_enter_write(__u64 fd, char *buf, __u64 size) {
    __u64 id = bpf_get_current_pid_tgid();
    struct l7_request req = {};
    req.partial = 0;
    if (is_http_request(buf)) {
        req.protocol = PROTOCOL_HTTP;
    } else if (is_postgres_query(buf, size)) {
        req.protocol = PROTOCOL_POSTGRES;
    } else if (is_redis_query(buf)) {
        req.protocol = PROTOCOL_REDIS;
    } else if (is_memcached_query(buf, size)) {
        req.protocol = PROTOCOL_MEMCACHED;
    } else if (is_mysql_query(buf, size)) {
        req.protocol = PROTOCOL_MYSQL;
    } else if (is_mongo_query(buf, size)) {
        req.protocol = PROTOCOL_MONGO;
    } else {
        return 0;
    }
    req.ns = bpf_ktime_get_ns();
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = fd;
    bpf_map_update_elem(&active_l7_requests, &k, &req, BPF_ANY);
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
    char *buf;
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = args->fd;
    buf = args->buf;

    bpf_map_delete_elem(&active_reads, &id);
    if (ctx->ret <= 0) {
        return 0;
    }

    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!req) {
        return 0;
    }
    struct l7_event e = {};
    e.protocol = req->protocol;
    e.fd = k.fd;
    e.pid = k.pid;
    e.connection_timestamp = 0;
    __u64 ns = req->ns;
    __u8 partial = req->partial;
    bpf_map_delete_elem(&active_l7_requests, &k);

    if (req->protocol == PROTOCOL_HTTP) {
        e.status = parse_http_status(buf);
    } else if (req->protocol == PROTOCOL_POSTGRES) {
        e.status = parse_postgres_status(buf, ctx->ret);
    } else if (req->protocol == PROTOCOL_REDIS) {
        e.status = parse_redis_status(buf, ctx->ret);
    } else if (req->protocol == PROTOCOL_MEMCACHED) {
        e.status = parse_memcached_status(buf, ctx->ret);
    } else if (req->protocol == PROTOCOL_MYSQL) {
        e.status = parse_mysql_status(buf, ctx->ret);
    } else if (req->protocol == PROTOCOL_MONGO) {
        e.status = parse_mongo_status(buf, ctx->ret, partial);
        if (e.status == 1) {
            struct l7_request r = {};
            r.partial = 1;
            r.protocol = e.protocol;
            r.ns = ns;
            bpf_map_update_elem(&active_l7_requests, &k, &r, BPF_ANY);
            return 0;
        }
    }
    if (e.status == 0) {
        return 0;
    }
    e.duration = bpf_ktime_get_ns() - ns;
    __u64 *timestamp = bpf_map_lookup_elem(&connection_timestamps, &k);
    if (timestamp) {
        e.connection_timestamp = *timestamp;
    }
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    struct iov iov0 = {};
    if (bpf_probe_read(&iov0, sizeof(struct iov), (void *)ctx->buf) < 0) {
        return 0;
    }
    return trace_enter_write(ctx->fd, iov0.buf, iov0.size);
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx->fd, ctx->buf, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx->fd, ctx->buf, ctx->size);
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
