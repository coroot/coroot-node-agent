// Redis serialization protocol (RESP) specification
// https://redis.io/docs/reference/protocol-spec/

static __always_inline
int is_redis_query(char *buf) {
    char b[5];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }
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
__u32 parse_redis_status(char *buf, int buf_size) {
    char type;
    char end[2];
    if (bpf_probe_read(&type, sizeof(type), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (bpf_probe_read(&end, sizeof(end), (void *)((char *)buf+buf_size-2)) < 0) {
        return 0;
    }
    if (end[0] != '\r' || end[1] != '\n') {
        return 0;
    }
    if (type == '*' || type == ':' || type == '$' || type == '+') {
        return 200;
    }
    if (type == '-') {
        return 500;
    }
    return 0;
}
