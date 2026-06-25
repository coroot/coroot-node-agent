// Redis serialization protocol (RESP) specification
// https://redis.io/docs/reference/protocol-spec/

static __always_inline
int redis_matches_query_shape(char *buf, __u64 buf_size) {
    if (buf_size < 11) {
        return 0;
    }
    char b[12];
    bpf_read(buf, b);
    if (b[0] != '*' || b[1] < '0' || b[1] > '9') {
        return 0;
    }
    int p;
    if (b[2] == '\r' && b[3] == '\n') { // *3\r\n...
        p = 4;
    } else if (b[2] >= '0' && b[2] <= '9' && b[3] == '\r' && b[4] == '\n') { // *12\r\n...
        p = 5;
    } else {
        return 0;
    }

    if (b[p] != '$' || b[p+1] < '0' || b[p+1] > '9') {
        return 0;
    }
    int cmd_pos;
    if (b[p+2] == '\r' && b[p+3] == '\n') {
        cmd_pos = p + 4;
    } else if (p+4 < 12 && b[p+2] >= '0' && b[p+2] <= '9' && b[p+3] == '\r' && b[p+4] == '\n') {
        cmd_pos = p + 5;
    } else {
        return 0;
    }
    if (cmd_pos >= 12) {
        return 0;
    }
    char c = b[cmd_pos];
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static __always_inline
int is_redis_query(char *buf, __u64 buf_size) {
    return redis_matches_query_shape(buf, buf_size);
}

static __always_inline
int is_redis_response(char *buf, __u64 buf_size, __s32 *status) {
    if (buf_size < 3) {
        return 0;
    }
    char type;
    bpf_read(buf, type);

    if (type == '*' && redis_matches_query_shape(buf, buf_size)) {
        return 0;
    }

    if (type == '*' || type == '$' || type == ':' || type == '+' ||
        type == '_' || type == '#' || type == ',' || type == '(' ||
        type == '=' || type == '~' || type == '>' || type == '%' || type == '|') {
        *status = STATUS_OK;
        return 1;
    }
    if (type == '-' || type == '!') {
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}
