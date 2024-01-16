#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_HTTP	    1
#define PROTOCOL_POSTGRES	2
#define PROTOCOL_REDIS	    3
#define PROTOCOL_MEMCACHED  4
#define PROTOCOL_MYSQL      5
#define PROTOCOL_MONGO      6
#define PROTOCOL_KAFKA      7
#define PROTOCOL_CASSANDRA  8
#define PROTOCOL_RABBITMQ   9
#define PROTOCOL_NATS      10
#define PROTOCOL_HTTP2	   11
#define PROTOCOL_DUBBO2    12

#define STATUS_UNKNOWN  0
#define STATUS_OK       200
#define STATUS_FAILED   500

#define METHOD_UNKNOWN              0
#define METHOD_PRODUCE              1
#define METHOD_CONSUME              2
#define METHOD_STATEMENT_PREPARE    3
#define METHOD_STATEMENT_CLOSE      4
#define METHOD_HTTP2_CLIENT_FRAMES  5
#define METHOD_HTTP2_SERVER_FRAMES  6

#define MAX_PAYLOAD_SIZE 1024 // must be power of 2
#define TRUNCATE_PAYLOAD_SIZE(size) ({                                  \
    size = MIN(size, MAX_PAYLOAD_SIZE-1);                               \
    asm volatile ("%0 &= %1" : "+r"(size) : "i"(MAX_PAYLOAD_SIZE-1));   \
})
#define COPY_PAYLOAD(dst, size, src) ({     \
    TRUNCATE_PAYLOAD_SIZE(size);            \
    if (bpf_probe_read(dst, size, src)) {   \
        return 0;                           \
    }                                       \
})

#define IOVEC_BUF_SIZE MAX_PAYLOAD_SIZE * 2  // must be double of MAX_PAYLOAD_SIZE
#define MAX_IOVEC_SIZE 32

#include "http.c"
#include "postgres.c"
#include "redis.c"
#include "memcached.c"
#include "mysql.c"
#include "mongo.c"
#include "kafka.c"
#include "cassandra.c"
#include "rabbitmq.c"
#include "nats.c"
#include "http2.c"
#include "dubbo2.c"

struct l7_event {
    __u64 fd;
    __u64 connection_timestamp;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    __u32 statement_id;
    __u64 payload_size;
    char payload[MAX_PAYLOAD_SIZE];
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

struct read_args {
    __u64 fd;
    char* buf;
    __u64* ret;
    __u64 iovlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct l7_request_key {
    __u64 fd;
    __u32 pid;
    __u16 is_tls;
    __s16 stream_id;
};

struct l7_request {
    __u64 ns;
    __u8 protocol;
    __u8 partial;
    __u8 request_type;
    __s32 request_id;
    __u64 payload_size;
    char payload[MAX_PAYLOAD_SIZE];
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct l7_request_key));
    __uint(value_size, sizeof(struct l7_request));
    __uint(max_entries, 32768);
} active_l7_requests SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, char[IOVEC_BUF_SIZE]);
     __uint(max_entries, 1);
} iovec_buf_heap SEC(".maps");

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

struct iovec {
    char* buf;
    __u64 size;
};

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__u64 msg_iovlen;
};

static inline __attribute__((__always_inline__))
__u64 get_connection_timestamp(__u32 pid, __u64 fd) {
    struct sk_info sk = {};
    sk.pid = pid;
    sk.fd = fd;
    __u64 *timestamp = bpf_map_lookup_elem(&connection_timestamps, &sk);
    if (timestamp) {
        return *timestamp;
    }
    return 0;
}

static inline __attribute__((__always_inline__))
__u64 read_iovec(char *iovec, __u64 iovlen, __u64 ret, char *buf) {
    struct iovec iov = {};
    __u64 max = (ret) ? MIN(ret, MAX_PAYLOAD_SIZE) : MAX_PAYLOAD_SIZE;
    __u64 offset = 0;
    __u64 size = 0;
    #pragma unroll
    for (int i = 0; i < MAX_IOVEC_SIZE; i++) {
        if (i >= iovlen) {
            break;
        }
        if (bpf_probe_read(&iov, sizeof(iov), (void *)(iovec+i*sizeof(iov)))) {
            return 0;
        }
        if (iov.size <= 0) {
            continue;
        }
        size = MIN(iov.size, max-offset);
        TRUNCATE_PAYLOAD_SIZE(size);
        TRUNCATE_PAYLOAD_SIZE(offset);
        if (bpf_probe_read(buf + offset, size, (void *)iov.buf)) {
            return 0;
        }
        offset += size;
        if (offset >= max) {
            break;
        }
    }
    return offset;
}

static inline __attribute__((__always_inline__))
int trace_enter_write(void *ctx, __u64 fd, __u16 is_tls, char *buf, __u64 size, __u64 iovlen) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 zero = 0;

    char* payload = buf;
    if (iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        size = read_iovec(buf, iovlen, 0, payload);
    }
    if (!size) {
        return 0;
    }

    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }
    req->protocol = PROTOCOL_UNKNOWN;
    req->partial = 0;
    req->request_id = 0;
    req->ns = 0;
    req->payload_size = size;
    struct l7_request_key k = {};
    k.pid = id >> 32;
    k.fd = fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    if (is_http_request(payload)) {
        req->protocol = PROTOCOL_HTTP;
    } else if (is_postgres_query(payload, size, &req->request_type)) {
        if (req->request_type == POSTGRES_FRAME_CLOSE) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_POSTGRES;
            e->fd = k.fd;
            e->pid = k.pid;
            e->method = METHOD_STATEMENT_CLOSE;
            e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
            e->payload_size = size;
            COPY_PAYLOAD(e->payload, size, payload);
            bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            return 0;
        }
        req->protocol = PROTOCOL_POSTGRES;
    } else if (is_redis_query(payload, size)) {
        req->protocol = PROTOCOL_REDIS;
    } else if (is_memcached_query(payload, size)) {
        req->protocol = PROTOCOL_MEMCACHED;
    } else if (is_mysql_query(payload, size, &req->request_type)) {
        if (req->request_type == MYSQL_COM_STMT_CLOSE) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_MYSQL;
            e->fd = k.fd;
            e->pid = k.pid;
            e->method = METHOD_STATEMENT_CLOSE;
            e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
            e->payload_size = size;
            COPY_PAYLOAD(e->payload, size, payload);
            bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            return 0;
        }
        req->protocol = PROTOCOL_MYSQL;
    } else if (is_mongo_query(payload, size)) {
        req->protocol = PROTOCOL_MONGO;
    } else if (is_rabbitmq_produce(payload, size)) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_RABBITMQ;
        e->fd = k.fd;
        e->pid = k.pid;
        e->method = METHOD_PRODUCE;
        e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    } else if (nats_method(payload, size) == METHOD_PRODUCE) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_NATS;
        e->fd = k.fd;
        e->pid = k.pid;
        e->method = METHOD_PRODUCE;
        e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    } else if (is_cassandra_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_CASSANDRA;
    } else if (is_kafka_request(payload, size, &req->request_id)) {
        req->protocol = PROTOCOL_KAFKA;
        struct l7_request *prev_req = bpf_map_lookup_elem(&active_l7_requests, &k);
        if (prev_req && prev_req->protocol == PROTOCOL_KAFKA) {
            req->ns = prev_req->ns;
        }
    } else if (looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_HTTP2;
        e->fd = k.fd;
        e->pid = k.pid;
        e->method = METHOD_HTTP2_CLIENT_FRAMES;
        e->duration = bpf_ktime_get_ns();
        e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
        e->payload_size = size;
        COPY_PAYLOAD(e->payload, size, payload);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    } else if (is_dubbo2_request(payload, size)) {
        req->protocol = PROTOCOL_DUBBO2;
    }

    if (req->protocol == PROTOCOL_UNKNOWN) {
        return 0;
    }
    if (req->ns == 0) {
        req->ns = bpf_ktime_get_ns();
    }
    COPY_PAYLOAD(req->payload, size, payload);
    bpf_map_update_elem(&active_l7_requests, &k, req, BPF_NOEXIST);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_enter_read(__u64 id, __u64 fd, char *buf, __u64 *ret, __u64 iovlen) {
    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.ret = ret;
    args.iovlen = iovlen;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_exit_read(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret) {
    struct read_args *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }

    struct l7_request_key k = {};
    k.pid = pid;
    k.fd = args->fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    bpf_map_delete_elem(&active_reads, &id);

    if (ret <= 0) {
        return 0;
    }
    if (args->ret) {
        if (bpf_probe_read(&ret, sizeof(ret), (void*)args->ret)) {
            return 0;
        };
        if (ret <= 0) {
            return 0;
        }
    }

    int zero = 0;
    char* payload = args->buf;
    if (args->iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        ret = read_iovec(args->buf, args->iovlen, ret, payload);
        if (!ret) {
            return 0;
        }
    }

    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }
    e->fd = k.fd;
    e->pid = k.pid;
    e->protocol = PROTOCOL_UNKNOWN;
    e->connection_timestamp = 0;
    e->status = STATUS_UNKNOWN;
    e->method = METHOD_UNKNOWN;
    e->statement_id = 0;
    e->payload_size = 0;

    if (is_rabbitmq_consume(payload, ret)) {
        e->protocol = PROTOCOL_RABBITMQ;
        e->method = METHOD_CONSUME;
        e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    }
    if (nats_method(payload, ret) == METHOD_CONSUME) {
        e->protocol = PROTOCOL_NATS;
        e->method = METHOD_CONSUME;
        e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    }

    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    int response = 0;
    if (!req) {
        if (is_cassandra_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            response = 1;
        } else if (looks_like_http2_frame(payload, ret, METHOD_HTTP2_SERVER_FRAMES)) {
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_SERVER_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
            e->payload_size = ret;
            COPY_PAYLOAD(e->payload, ret, payload);
            bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            return 0;
        } else {
            return 0;
        }
    }

    e->protocol = req->protocol;
    e->payload_size = req->payload_size;
    COPY_PAYLOAD(e->payload, req->payload_size, req->payload);

    bpf_map_delete_elem(&active_l7_requests, &k);
    if (e->protocol == PROTOCOL_HTTP) {
        response = is_http_response(payload, &e->status);
    } else if (e->protocol == PROTOCOL_POSTGRES) {
        response = is_postgres_response(payload, ret, &e->status);
        if (req->request_type == POSTGRES_FRAME_PARSE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_REDIS) {
        response = is_redis_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MEMCACHED) {
        response = is_memcached_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MYSQL) {
        response = is_mysql_response(payload, ret, req->request_type, &e->statement_id, &e->status);
        if (req->request_type == MYSQL_COM_STMT_PREPARE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_MONGO) {
        response = is_mongo_response(payload, ret, req->partial);
        if (response == 2) { // partial
            struct l7_request *r = bpf_map_lookup_elem(&l7_request_heap, &zero);
            if (!r) {
                return 0;
            }
            r->partial = 1;
            r->protocol = e->protocol;
            r->ns = req->ns;
            r->payload_size = req->payload_size;
            COPY_PAYLOAD(r->payload, req->payload_size, req->payload);
            bpf_map_update_elem(&active_l7_requests, &k, r, BPF_ANY);
            return 0;
        }
    } else if (e->protocol == PROTOCOL_KAFKA) {
        response = is_kafka_response(payload, req->request_id);
    } else if (e->protocol == PROTOCOL_DUBBO2) {
        response = is_dubbo2_response(payload, &e->status);
    }

    if (!response) {
        return 0;
    }
    e->duration = bpf_ktime_get_ns() - req->ns;
    e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size, 0);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, 0, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sys_enter_sendmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    return trace_enter_write(ctx, ctx->fd, 0, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size, 0);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    return trace_enter_read(id, ctx->fd, ctx->buf, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    return trace_enter_read(id, ctx->fd, ctx->buf, 0, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int sys_enter_recvmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    return trace_enter_read(id, ctx->fd, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    return trace_enter_read(id, ctx->fd, ctx->buf, 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int sys_exit_readv(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int sys_exit_recvmsg(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}
