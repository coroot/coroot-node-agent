// Redis serialization protocol (RESP) specification
// https://redis.io/docs/reference/protocol-spec/

static __always_inline
int is_redis_query(char *buf, __u64 buf_size) {
    if (buf_size < 5) {
        return 0;
    }
    char b[5];
    bpf_read(buf, b);
    if (b[0] != '*' || b[1] < '0' || b[1] > '9') {
        return 0;
    }
    // *3\r\n...
    if (b[2] == '\r' && b[3] == '\n') {
        return 1;
    }
    // *12\r\n...
    if (b[2] >= '0' && b[2] <= '9' && b[3] == '\r' && b[4] == '\n') {
        return 1;
    }
    return 0;
}

static __always_inline
int is_redis_response(char *buf, __u64 buf_size, __u32 *status) {
    char type;
    bpf_read(buf, type);
    char end[2];
    TRUNCATE_PAYLOAD_SIZE(buf_size);
    bpf_read(buf+buf_size-2, end);
    if (end[0] != '\r' || end[1] != '\n') {
        return 0;
    }
    if (type == '*' || type == ':' || type == '$' || type == '+') {
        *status = STATUS_OK;
        return 1;
    }
    if (type == '-') {
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}
