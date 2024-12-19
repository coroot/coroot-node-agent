#define CLICKHOUSE_QUERY_ID_SIZE 36

#define CLICKHOUSE_QUERY_KIND_INITIAL 1
#define CLICKHOUSE_QUERY_KIND_SECONDARY 2

#define CLICKHOUSE_CLIENT_CODE_QUERY 1

#define CLICKHOUSE_SERVER_CODE_DATA 1
#define CLICKHOUSE_SERVER_CODE_EXCEPTION 2
#define CLICKHOUSE_SERVER_CODE_END_OF_STREAM 5

static __always_inline
int is_clickhouse_query(char *buf, __u64 buf_size) {
    __u8 b[CLICKHOUSE_QUERY_ID_SIZE+3];
    if (bpf_probe_read(&b, sizeof(b), (void *)buf) < 0) {
        return 0;
    }
    if (b[0] != CLICKHOUSE_CLIENT_CODE_QUERY) {
        return 0;
    }
    int offset = 0;
    if (b[1] == 0) {
        offset = 2;
    } else if (b[1] == CLICKHOUSE_QUERY_ID_SIZE) {
        offset = 2 + CLICKHOUSE_QUERY_ID_SIZE;
    } else {
        return 0;
    }
    if (b[offset] != CLICKHOUSE_QUERY_KIND_INITIAL && b[offset] != CLICKHOUSE_QUERY_KIND_SECONDARY) {
        return 0;
    }
    return 1;
}

static __always_inline
int is_clickhouse_response(char *buf, __u32 *status) {
    __u8 code = 0;
    if (bpf_probe_read(&code, sizeof(code), (void *)buf) < 0) {
        return 0;
    }
    if (code == CLICKHOUSE_SERVER_CODE_DATA || code == CLICKHOUSE_SERVER_CODE_END_OF_STREAM) {
        *status = STATUS_OK;
        return 1;
    }
    if (code == CLICKHOUSE_SERVER_CODE_EXCEPTION) {
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}
