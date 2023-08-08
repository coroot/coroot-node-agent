#include "http.c"
#include "postgres.c"
#include "redis.c"
#include "memcached.c"
#include "mysql.c"
#include "mongo.c"
#include "kafka.c"
#include "cassandra.c"
#include "rabbitmq.c"

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

#define METHOD_UNKNOWN           0
#define METHOD_PRODUCE           1
#define METHOD_CONSUME           2
#define METHOD_STATEMENT_PREPARE 3
#define METHOD_STATEMENT_CLOSE   4

#define MAX_PAYLOAD_SIZE 512

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
    char payload[MAX_PAYLOAD_SIZE];
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
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
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct socket_key {
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
    char payload[MAX_PAYLOAD_SIZE];
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

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

struct iovec {
    char* buf;
    __u64 size;
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
int trace_enter_write(void *ctx, __u64 fd, __u16 is_tls, char *buf, __u64 size) {
    __u64 id = bpf_get_current_pid_tgid();
    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }
    req->protocol = PROTOCOL_UNKNOWN;
    req->partial = 0;
    req->request_id = 0;
    req->ns = 0;
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    if (is_http_request(buf)) {
        req->protocol = PROTOCOL_HTTP;
    } else if (is_postgres_query(buf, size, &req->request_type)) {
        if (req->request_type == POSTGRES_FRAME_CLOSE) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_POSTGRES;
            e->fd = k.fd;
            e->pid = k.pid;
            e->method = METHOD_STATEMENT_CLOSE;
            e->status = 200;
            e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
            bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, (void *)buf);
            bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            return 0;
        }
        req->protocol = PROTOCOL_POSTGRES;
    } else if (is_redis_query(buf)) {
        req->protocol = PROTOCOL_REDIS;
    } else if (is_memcached_query(buf, size)) {
        req->protocol = PROTOCOL_MEMCACHED;
    } else if (is_mysql_query(buf, size, &req->request_type)) {
        if (req->request_type == MYSQL_COM_STMT_CLOSE) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_MYSQL;
            e->fd = k.fd;
            e->pid = k.pid;
            e->method = METHOD_STATEMENT_CLOSE;
            e->status = 200;
            e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
            bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, (void *)buf);
            bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            return 0;
        }
        req->protocol = PROTOCOL_MYSQL;
    } else if (is_mongo_query(buf, size)) {
        req->protocol = PROTOCOL_MONGO;
    } else if (is_rabbitmq_produce(buf, size)) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_RABBITMQ;
        e->fd = k.fd;
        e->pid = k.pid;
        e->status = 200;
        e->method = METHOD_PRODUCE;
        e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
        bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, (void *)buf);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    } else {
        __s32 request_id = is_kafka_request(buf, size);
        if  (request_id > 0) {
            req->request_id = request_id;
            req->protocol = PROTOCOL_KAFKA;
            struct l7_request *prev_req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (prev_req && prev_req->protocol == PROTOCOL_KAFKA) {
                req->ns = prev_req->ns;
            }
        } else {
            __s16 stream_id = is_cassandra_request(buf, size);
            if  (stream_id != -1) {
                k.stream_id = stream_id;
                req->protocol = PROTOCOL_CASSANDRA;
            }
        }
    }
    if (req->protocol == PROTOCOL_UNKNOWN) {
        return 0;
    }
    if (req->ns == 0) {
        req->ns = bpf_ktime_get_ns();
    }
    bpf_probe_read(req->payload, MAX_PAYLOAD_SIZE, (void *)buf);
    bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_enter_read(__u64 id, __u64 fd, char *buf) {
    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_exit_read(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret) {
    struct read_args *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }
    struct socket_key k = {};
    k.pid = pid;
    k.fd = args->fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    bpf_map_delete_elem(&active_reads, &id);

    if (ret <= 0) {
        return 0;
    }

    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }
    e->fd = k.fd;
    e->pid = k.pid;
    e->connection_timestamp = 0;
    e->status = 0;
    e->method = METHOD_UNKNOWN;
    e->statement_id = 0;

    if (is_rabbitmq_consume(args->buf, ret)) {
        e->protocol = PROTOCOL_RABBITMQ;
        e->status = 200;
        e->method = METHOD_CONSUME;
        e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    }

    struct cassandra_header cassandra_response = {};
    cassandra_response.stream_id = -1;
    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!req) {
        if (bpf_probe_read(&cassandra_response, sizeof(cassandra_response), (void *)(args->buf)) < 0) {
            return 0;
        }
        k.stream_id = cassandra_response.stream_id;
        req = bpf_map_lookup_elem(&active_l7_requests, &k);
        if (!req) {
            return 0;
        }
    }

    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, req->payload);
    __s32 request_id = req->request_id;
    e->protocol = req->protocol;
    __u64 ns = req->ns;
    __u8 partial = req->partial;
    __u8 request_type = req->request_type;
    bpf_map_delete_elem(&active_l7_requests, &k);
    if (e->protocol == PROTOCOL_HTTP) {
        e->status = parse_http_status(args->buf);
    } else if (e->protocol == PROTOCOL_POSTGRES) {
        e->status = parse_postgres_status(args->buf, ret);
        if (request_type == POSTGRES_FRAME_PARSE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_REDIS) {
        e->status = parse_redis_status(args->buf, ret);
    } else if (e->protocol == PROTOCOL_MEMCACHED) {
        e->status = parse_memcached_status(args->buf, ret);
    } else if (e->protocol == PROTOCOL_MYSQL) {
        e->status = parse_mysql_response(args->buf, ret, request_type, &e->statement_id);
        if (request_type == MYSQL_COM_STMT_PREPARE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_MONGO) {
        e->status = parse_mongo_status(args->buf, ret, partial);
        if (e->status == 1) {
            struct l7_request *r = bpf_map_lookup_elem(&l7_request_heap, &zero);
            if (!r) {
                return 0;
            }
            r->partial = 1;
            r->protocol = e->protocol;
            r->ns = ns;
            bpf_probe_read(r->payload, MAX_PAYLOAD_SIZE, e->payload);
            bpf_map_update_elem(&active_l7_requests, &k, r, BPF_ANY);
            return 0;
        }
    } else if (e->protocol == PROTOCOL_KAFKA) {
        e->status = parse_kafka_status(request_id, args->buf, ret, partial);
    } else if (e->protocol == PROTOCOL_CASSANDRA) {
        e->status = cassandra_status(cassandra_response);
    }
    if (e->status == 0) {
        return 0;
    }
    e->duration = bpf_ktime_get_ns() - ns;
    e->connection_timestamp = get_connection_timestamp(k.pid, k.fd);
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    struct iovec iovec0 = {};
    if (bpf_probe_read(&iovec0, sizeof(struct iovec), (void *)ctx->buf) < 0) {
        return 0;
    }
    return trace_enter_write(ctx, ctx->fd, 0, iovec0.buf, iovec0.size);
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    return trace_enter_read(id, ctx->fd, ctx->buf);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct iovec iovec0 = {};
    if (bpf_probe_read(&iovec0, sizeof(struct iovec), (void *)ctx->buf) < 0) {
        return 0;
    }
    return trace_enter_read(id, ctx->fd, iovec0.buf);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    return trace_enter_read(id, ctx->fd, ctx->buf);
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

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}
