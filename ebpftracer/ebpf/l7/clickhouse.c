#define CLICKHOUSE_QUERY_ID_SIZE 36

#define CLICKHOUSE_QUERY_KIND_INITIAL 1
#define CLICKHOUSE_QUERY_KIND_SECONDARY 2

#define CLICKHOUSE_CLIENT_CODE_QUERY 1

#define CLICKHOUSE_SERVER_CODE_DATA 1
#define CLICKHOUSE_SERVER_CODE_EXCEPTION 2
#define CLICKHOUSE_SERVER_CODE_END_OF_STREAM 5

#define CLICKHOUSE_COMPRESSION_NONE 0x02
#define CLICKHOUSE_COMPRESSION_LZ4  0x82
#define CLICKHOUSE_COMPRESSION_ZSTD 0x90

#define CLICKHOUSE_MIN_QUERY_SIZE 40
#define CLICKHOUSE_MAX_USER_SIZE 63
#define CLICKHOUSE_MAX_ADDRESS_SIZE 48

// the max legitimate offset within the query header is 197 (2+36+1+1+63+1+36+1+48+8)
#define CLICKHOUSE_MAX_OFFSET 200 // checking this fixes the program load on 5.4

static __always_inline
int is_clickhouse_uuid(char *buf) {
    __u8 u[CLICKHOUSE_QUERY_ID_SIZE];
    bpf_read(buf, u);
    if (u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-') {
        return 0;
    }
    return 1;
}

static __always_inline
int is_clickhouse_query(char *buf, __u64 buf_size) {
    if (buf_size < CLICKHOUSE_MIN_QUERY_SIZE) {
        return 0;
    }
    __u8 b[2];
    bpf_read(buf, b);
    if (b[0] != CLICKHOUSE_CLIENT_CODE_QUERY) {
        return 0;
    }
    __u64 offset = 2;
    if (b[1] == CLICKHOUSE_QUERY_ID_SIZE) {
        if (!is_clickhouse_uuid(buf+2)) {
            return 0;
        }
        offset += CLICKHOUSE_QUERY_ID_SIZE;
    } else if (b[1] != 0) {
        return 0;
    }
    __u8 kind = 0;
    bpf_read(buf+offset, kind);
    if (kind != CLICKHOUSE_QUERY_KIND_INITIAL && kind != CLICKHOUSE_QUERY_KIND_SECONDARY) {
        return 0;
    }
    offset += 1;
    __u8 len = 0;
    bpf_read(buf+offset, len); // initial_user
    if (len > CLICKHOUSE_MAX_USER_SIZE) {
        return 0;
    }
    offset += 1 + len;
    if (offset > CLICKHOUSE_MAX_OFFSET) {
        return 0;
    }
    bpf_read(buf+offset, len); // initial_query_id
    if (len == CLICKHOUSE_QUERY_ID_SIZE) {
        if (!is_clickhouse_uuid(buf+offset+1)) {
            return 0;
        }
    } else if (len != 0) {
        return 0;
    }
    offset += 1 + len;
    if (offset > CLICKHOUSE_MAX_OFFSET) {
        return 0;
    }
    bpf_read(buf+offset, len); // initial_address
    if (len > CLICKHOUSE_MAX_ADDRESS_SIZE) {
        return 0;
    }
    if (len > 0) {
        __u8 c = 0;
        bpf_read(buf+offset+1, c);
        if (!((c >= '0' && c <= '9') || c == '[' || c == ':')) {
            return 0;
        }
    }
    offset += 1 + len + 8; // interface follows the 8-byte initial_query_start_time_microseconds
    if (offset > CLICKHOUSE_MAX_OFFSET || offset >= buf_size) {
        return 0;
    }
    __u8 iface = 0;
    bpf_read(buf+offset, iface); // TCP, HTTP, GRPC, MYSQL, POSTGRESQL, LOCAL, TCP_INTERSERVER, PROMETHEUS
    if (iface < 1 || iface > 8) {
        return 0;
    }
    return 1;
}

static __always_inline
int is_clickhouse_response(char *buf, __u64 buf_size, __s32 *status) {
    __u8 b[3];
    bpf_read(buf, b);
    if (b[0] == CLICKHOUSE_SERVER_CODE_DATA) {
        if (b[1] != 0) { // temporary table name is always empty
            return 0;
        }
        if (b[2] == 1) { // uncompressed block: BlockInfo field number 1
            *status = STATUS_OK;
            return 1;
        }
        __u8 method = 0;
        bpf_read(buf+2+16, method); // compressed block: compression method follows the 16-byte checksum
        if (method == CLICKHOUSE_COMPRESSION_LZ4 || method == CLICKHOUSE_COMPRESSION_ZSTD || method == CLICKHOUSE_COMPRESSION_NONE) {
            *status = STATUS_OK;
            return 1;
        }
        return 0;
    }
    if (b[0] == CLICKHOUSE_SERVER_CODE_EXCEPTION) {
        __s32 code = 0;
        bpf_read(buf+1, code);
        if (code <= 0 || code > 4096) {
            return 0;
        }
        *status = STATUS_FAILED;
        return 1;
    }
    if (b[0] == CLICKHOUSE_SERVER_CODE_END_OF_STREAM && buf_size == 1) {
        *status = STATUS_OK;
        return 1;
    }
    return 0;
}
