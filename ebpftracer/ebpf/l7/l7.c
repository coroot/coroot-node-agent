// L7 request/response monitoring, both client-side and server-side

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
#define PROTOCOL_DNS       13

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
#include "dns.c"

// ===== client-side =====
// L7 request monitoring from the client-side. First WRITE then READ.

struct l7_event {
    __u64 fd;
    __u64 connection_timestamp;  // connection timestamp instead of the span start timestamp, actually unused from the GoLang part
    __u32 pid;
    __u64 tgid_write;  // tgid who sends the request
    __u64 tgid_read;  // tgid who receives the response
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    __u32 statement_id;
    __u64 payload_size;
    char payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed));

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  // non-historical store, Array, not LRU
     __type(key, int);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");  // heap is used to share (and save) memory between each protocol parser

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");  // PerfMap's specific map format

struct read_args {
    __u64 fd;
    char* buf;
    __u64* ret;
    __u64 iovlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));  // Uses tgid, or introduced goroutine_id. Totally matches the smallest executor.
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct l7_request_key {
    __u64 fd;
    __u32 pid;
    __u16 is_tls;
    __s16 stream_id;
};

struct l7_request {  // more like concept `flow`, maybe request, maybe response
    __u64 ns;  // timestamp when sends the request
    __u64 tgid_send;  // tgid who sends the request
    __u64 tgid_recv;  // tgid who receives the response, unused actually
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
} l7_request_heap SEC(".maps");  // Heap is used to share memory. Besides, eBPF stack has limited memory.

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct l7_request_key));
    __uint(value_size, sizeof(struct l7_request));
    __uint(max_entries, 32768);
} active_l7_requests SEC(".maps");  // 类似 `active_connections`，是针对 L7 的，同样限制于 client-side。

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, char[IOVEC_BUF_SIZE]);
     __uint(max_entries, 1);
} iovec_buf_heap SEC(".maps");

struct trace_event_raw_sys_enter_rw__stub {
    __u64 unused;
    long int id;  // 系统调用编号，表示当前调用的具体系统调用，比如在 sys_enter_write 中应该是 SYS_write，即 write 的系统调用号。
    __u64 fd;  // write 系统调用的第一个参数，表示文件描述符（file descriptor，fd），指明数据要写入的文件或设备。
    char* buf;  // write 系统调用的第二个参数，表示要写入的数据的缓冲区地址，这个指针指向用户空间的缓冲区。
    __u64 size;  // write 系统调用的第三个参数，表示要写入的字节数。
};

struct trace_event_raw_sys_exit_rw__stub {
    __u64 unused;
    long int id;  // 系统调用号，可以用来确认是否是 read 系统调用。
    long int ret;  // 系统调用返回值，即 read 返回的值。调用成功时为读取的字节数，失败时为负数的错误码。
};

// I/O vector, parameter for readv/writev
struct iovec {
    char* buf;
    __u64 size;
};

// user message header：应用层消息头
struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__u64 msg_iovlen;
	void *msg_control;
    __u64 msg_controllen;
    __u32 msg_flags;
};

static inline __attribute__((__always_inline__))
void send_event(void *ctx, struct l7_event *e, struct connection_id cid, struct connection *conn) {
    e->connection_timestamp = conn->timestamp;
    e->fd = cid.fd;
    e->pid = cid.pid;
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
}

static inline __attribute__((__always_inline__))
__u64 read_iovec(char *iovec, __u64 iovlen, __u64 ret, char *buf, __u64 *total_size) {
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
        *total_size += iov.size;
        if (offset < max) {
            size = MIN(iov.size, max-offset);
            TRUNCATE_PAYLOAD_SIZE(size);
            TRUNCATE_PAYLOAD_SIZE(offset);
            if (bpf_probe_read(buf + offset, size, (void *)iov.buf)) {
                return 0;
            }
            offset += size;
        }
    }
    return offset;
}

static inline __attribute__((__always_inline__))
int trace_enter_write(void *ctx, __u64 fd, __u16 is_tls, char *buf, __u64 size, __u64 iovlen) {
    __u64 write_ns = bpf_ktime_get_ns();
    __u64 write_tgid = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct connection_id cid = {};
    cid.pid = write_tgid >> 32;
    cid.fd = fd;
    __u64 total_size = size;

    // filter from active_connections
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }

    char* payload = buf;
    if (iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        total_size = 0;
        size = read_iovec(buf, iovlen, 0, payload, &total_size);
    }
    if (!size) {
        return 0;
    }

    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_sent, total_size);
    }

    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }

    /* 对于 heap 的更新方式有两种。一种是这样先 lookup 再写成员。另一种是用 update ANY 写结构体。 */
    // reset req
    req->ns = 0;
    req->tgid_send = 0;
    req->tgid_recv = 0;
    req->protocol = PROTOCOL_UNKNOWN;
    req->partial = 0;
    req->request_id = 0;
    req->payload_size = size;

    struct l7_request_key k = {};
    k.pid = cid.pid;
    k.fd = cid.fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    if (is_http_request(payload)) {
        req->protocol = PROTOCOL_HTTP;
    } else if (is_postgres_query(payload, size, &req->request_type)) {
        if (req->request_type == POSTGRES_FRAME_CLOSE) {  // this request is the end of the pg stream query
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_POSTGRES;
            e->method = METHOD_STATEMENT_CLOSE;
            e->tgid_write = write_tgid;
            e->tgid_read = write_tgid;  // maybe the pg_server is single thread, for networking
            e->payload_size = size;
            COPY_PAYLOAD(e->payload, size, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        }
        req->protocol = PROTOCOL_POSTGRES;
    } else if (is_redis_query(payload, size)) {
        req->protocol = PROTOCOL_REDIS;
    } else if (is_memcached_query(payload, size)) {
        req->protocol = PROTOCOL_MEMCACHED;
    } else if (is_mysql_query(payload, size, &req->request_type)) {
        if (req->request_type == MYSQL_COM_STMT_CLOSE) {  // this request is the end of the mysql stream query
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_MYSQL;
            e->method = METHOD_STATEMENT_CLOSE;
            e->tgid_write = write_tgid;
            e->tgid_read = write_tgid;  // maybe the mysqld is single thread, for networking
            e->payload_size = size;
            COPY_PAYLOAD(e->payload, size, payload);
            send_event(ctx, e, cid, conn);
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
        e->method = METHOD_PRODUCE;
        e->tgid_write = write_tgid;
        e->tgid_read = write_tgid;  // checkme
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (nats_method(payload, size) == METHOD_PRODUCE) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_NATS;
        e->method = METHOD_PRODUCE;
        e->tgid_write = write_tgid;
        e->tgid_read = write_tgid;
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (is_cassandra_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_CASSANDRA;
    } else if (is_kafka_request(payload, size, &req->request_id)) {
        req->protocol = PROTOCOL_KAFKA;
        struct l7_request *prev_req = bpf_map_lookup_elem(&active_l7_requests, &k);
        if (prev_req && prev_req->protocol == PROTOCOL_KAFKA) {
            req->ns = prev_req->ns; // 这是由 Kafka 协议的“流水线”特性决定的。
        }
    } else if (looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_HTTP2;
        e->method = METHOD_HTTP2_CLIENT_FRAMES;
        // todo client-side tgid for writing http2
        e->duration = write_ns;
        e->payload_size = size;
        COPY_PAYLOAD(e->payload, size, payload);
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (is_dubbo2_request(payload, size)) {
        req->protocol = PROTOCOL_DUBBO2;
    } else if (is_dns_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_DNS;
    }

    if (req->protocol == PROTOCOL_UNKNOWN) {
        return 0;
    }

    req->ns = write_ns;
    req->tgid_send = write_tgid;
    req->tgid_recv = 0;

    COPY_PAYLOAD(req->payload, size, payload);

    bpf_map_update_elem(&active_l7_requests, &k, req, BPF_NOEXIST);  // req is REQUEST
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_exit_write(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret) {
    return 0; // nothing
}

static inline __attribute__((__always_inline__))
int trace_enter_read(__u64 id, __u32 pid, __u64 fd, char *buf, __u64 *ret, __u64 iovlen) {
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = fd;

    // filter from active_connections
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }

    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.ret = ret;
    args.iovlen = iovlen;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

// At READ:
// 1.Lookup `active_connections`, to find WRITE related context from the other side.
// 2.Lookup `active_l7_requests`, if this is a response, then find corresponding request.
static inline __attribute__((__always_inline__))
int trace_exit_read(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret) {
    __u64 read_ns = bpf_ktime_get_ns();
    __u64 read_tgid = bpf_get_current_pid_tgid();

    // filter from active_reads, between enter_read and exit_read
    struct read_args *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }

    // filter from active_connections
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = args->fd;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    bpf_map_delete_elem(&active_reads, &id);
    if (!conn) {
        return 0;
    }

    struct l7_request_key k = {};
    k.pid = cid.pid;
    k.fd = cid.fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    if (ret <= 0) {  // ret < 0, error in SYS_read; ret = 0, meets special file likes pipe.
        return 0;
    }
    if (args->ret) {
        if (bpf_probe_read(&ret, sizeof(ret), (void*)args->ret)) {
            return 0;
        }
        if (ret <= 0) {
            return 0;
        }
    }
    __u64 total_size = ret;  // I/O related syscalls return bytes exchanged.
    int zero = 0;
    char* payload = args->buf;
    if (args->iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        total_size = 0;
        ret = read_iovec(args->buf, args->iovlen, ret, payload, &total_size);
        if (!ret) {
            return 0;
        }
    }

    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_received, total_size);
    }

    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }

    // reset e
    e->protocol = PROTOCOL_UNKNOWN;
    e->status = STATUS_UNKNOWN;
    e->method = METHOD_UNKNOWN;
    e->statement_id = 0;
    e->payload_size = 0;
    e->tgid_write = 0;
    e->tgid_read = 0;

    if (is_rabbitmq_consume(payload, ret)) {
        e->protocol = PROTOCOL_RABBITMQ;
        e->method = METHOD_CONSUME;
        // todo tgid
        send_event(ctx, e, cid, conn);
        return 0;
    }
    if (nats_method(payload, ret) == METHOD_CONSUME) {
        e->protocol = PROTOCOL_NATS;
        e->method = METHOD_CONSUME;
        // todo tgid
        send_event(ctx, e, cid, conn);
        return 0;
    }

    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    int is_response = 0;  // 0: no, 1: yes, 2: partially
    if (!req) {
        if (is_dns_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            e->protocol = PROTOCOL_DNS;
            e->duration = read_ns - req->ns;
            e->payload_size = ret;
            COPY_PAYLOAD(e->payload, ret, payload);
            send_event(ctx, e, cid, conn);
            bpf_map_delete_elem(&active_l7_requests, &k);
            return 0;
        } else if (is_cassandra_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            is_response = 1;
        } else if (looks_like_http2_frame(payload, ret, METHOD_HTTP2_SERVER_FRAMES)) {
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_SERVER_FRAMES;
            e->duration = read_ns;
            e->payload_size = ret;
            COPY_PAYLOAD(e->payload, ret, payload);
            // todo client-side tgid for reading http2
            send_event(ctx, e, cid, conn);
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
        is_response = is_http_response(payload, &e->status);
    } else if (e->protocol == PROTOCOL_POSTGRES) {
        is_response = is_postgres_response(payload, ret, &e->status);
        if (req->request_type == POSTGRES_FRAME_PARSE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_REDIS) {
        is_response = is_redis_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MEMCACHED) {
        is_response = is_memcached_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MYSQL) {
        is_response = is_mysql_response(payload, ret, req->request_type, &e->statement_id, &e->status);
        if (req->request_type == MYSQL_COM_STMT_PREPARE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_MONGO) {
        is_response = is_mongo_response(payload, ret, req->partial);
        if (is_response == 2) { // partially
            struct l7_request *prev_req = bpf_map_lookup_elem(&l7_request_heap, &zero);
            if (!prev_req) {
                return 0;
            }
            prev_req->partial = 1;
            prev_req->protocol = e->protocol;
            prev_req->ns = req->ns;
            prev_req->payload_size = req->payload_size;
            COPY_PAYLOAD(prev_req->payload, req->payload_size, req->payload);
            bpf_map_update_elem(&active_l7_requests, &k, prev_req, BPF_ANY);
            return 0;
        }
    } else if (e->protocol == PROTOCOL_KAFKA) {
        is_response = is_kafka_response(payload, req->request_id);
    } else if (e->protocol == PROTOCOL_DUBBO2) {
        is_response = is_dubbo2_response(payload, &e->status);
    }

    if (!is_response) {
        return 0;
    }

    e->tgid_write = req->tgid_send;
    e->tgid_read = read_tgid;
    e->duration = read_ns - req->ns;
    send_event(ctx, e, cid, conn);
    return 0;
}

// ===== server-side =====
// L7 request monitoring from the server-side. First READ then WRITE.

struct l7_event_ss {
    __u64 fd;  // server socket fd
    __u32 pid;  // server pid
    __u64 timestamp;  // (kernel) timestamp when reads request from client, actually unused from the GoLang part
    __u64 duration;  // duration to nanoseconds when writing response to client, used from the GoLang part
    __u32 statement_id;  // some protocols may support request_id, like MySQL
    __u64 tgid_read;  // tgid who receives the request
    __u64 tgid_write;  // tgid who sends the response
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events_ss SEC(".maps");  // PerfMap's specific map format

struct l7_response_key {
    __u64 fd;
    __u32 pid;
};

struct l7_response {
    __u64 ns;  // (kernel) timestamp when receives the request
    __u64 tgid_recv;  // tgid who receives the request
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct l7_response_key));
    __uint(value_size, sizeof(struct l7_response));
    __uint(max_entries, 32768);
} active_l7_responses SEC(".maps");

struct write_args {
    __u64 fd;  // only fd needed
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct write_args));
    __uint(max_entries, 10240);
} active_writes SEC(".maps");

static inline __attribute__((__always_inline__))
int trace_ss_enter_read(__u64 id, __u32 pid, __u64 fd) {
    __u64 read_ns = bpf_ktime_get_ns();
    __u64 read_tgid = bpf_get_current_pid_tgid();

    // todo filter from active_connections_ss

    struct l7_response_key resp_key = {};
    resp_key.pid = pid;
    resp_key.fd = fd;

    struct l7_response resp = {};  // not use things like request heap, since it's very light
    resp.ns = read_ns;
    resp.tgid_recv = read_tgid;

    bpf_map_update_elem(&active_l7_responses, &resp_key, &resp, BPF_NOEXIST);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_ss_exit_read(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret) {
    return 0;  // nothing
}

static inline __attribute__((__always_inline__))
int trace_ss_enter_write(__u64 id, __u32 pid, __u64 fd) {
    // todo filter from active_connections_ss

    struct write_args args = {};
    args.fd = fd;
    bpf_map_update_elem(&active_writes, &id, &args, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_ss_exit_write(void *ctx, __u64 id, __u32 pid) {
    __u64 write_ns = bpf_ktime_get_ns();
    __u64 write_tgid = bpf_get_current_pid_tgid();

    struct write_args *args = bpf_map_lookup_elem(&active_writes, &id);
    if (!args) {
        return 0;
    }

    // todo filter from active_connections_ss

    struct l7_response_key resp_key = {};
    resp_key.pid = pid;
    resp_key.fd = args->fd;

    struct l7_response *resp = bpf_map_lookup_elem(&active_l7_responses, &resp_key);
    if (!resp) {
        return 0;
    }

    bpf_map_delete_elem(&active_l7_responses, &resp_key);

    struct l7_event_ss event = {};
    event.fd = resp_key.fd;
    event.pid = resp_key.pid;
    event.timestamp = resp->ns;
    event.duration = write_ns - resp->ns;
    event.tgid_read = resp->tgid_recv;
    event.tgid_write = write_tgid;

    // todo after filtering active_connections_ss, we could insert l7_events_ss

    bpf_perf_event_output(ctx, &l7_events_ss, BPF_F_CURRENT_CPU, &event, sizeof(struct l7_event_ss));

    return 0;
}

// ===== host registry =====
// enter write-like syscalls
SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size, 0);
    trace_ss_enter_write(id, pid, ctx->fd);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    trace_enter_write(ctx, ctx->fd, 0, ctx->buf, 0, ctx->size);
    trace_ss_enter_write(id, pid, ctx->fd);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sys_enter_sendmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }

    trace_enter_write(ctx, ctx->fd, 0, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
    trace_ss_enter_write(id, pid, ctx->fd);
    return 0;
}

struct mmsghdr {
	struct user_msghdr msg_hdr;
	__u32 msg_len;
};

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int sys_enter_sendmmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 offset = 0;
    #pragma unroll
    for (int i = 0; i <= 1; i++) {
        if (i >= ctx->size) {
            break;
        }
        struct mmsghdr h = {};
        if (bpf_probe_read(&h , sizeof(h), (void *)(ctx->buf + offset))) {
            return 0;
        }
        offset += sizeof(h);
        trace_enter_write(ctx, ctx->fd, 0, (char*)h.msg_hdr.msg_iov, 0, h.msg_hdr.msg_iovlen);
    }

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    trace_ss_enter_write(id, pid, ctx->fd);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size, 0);
    trace_ss_enter_write(id, pid, ctx->fd);
    return 0;
}

// exit write-like syscalls
SEC("tracepoint/syscalls/sys_exit_write")
int sys_exit_write(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    trace_ss_exit_write(ctx, id, pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int sys_exit_writev(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    trace_ss_exit_write(ctx, id, pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int sys_exit_sendmsg(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    trace_ss_exit_write(ctx, id, pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int sys_exit_sendto(struct trace_event_raw_sys_exit_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    trace_ss_exit_write(ctx, id, pid);
    return 0;
}

// todo temporarily not include sendmmsg

// enter read-like syscalls
SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    trace_enter_read(id, pid, ctx->fd, ctx->buf, 0, 0);
    trace_ss_enter_read(id, pid, ctx->fd);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    trace_enter_read(id, pid, ctx->fd, ctx->buf, 0, ctx->size);
    trace_ss_enter_read(id, pid, ctx->fd);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int sys_enter_recvmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, ctx->buf, 0, 0);
}

// exit read-like syscalls
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
