// https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec

#define CASSANDRA_REQUEST_FRAME  0x04
#define CASSANDRA_RESPONSE_FRAME 0x84

#define CASSANDRA_OPCODE_ERROR      0x00
#define CASSANDRA_OPCODE_QUERY      0x07
#define CASSANDRA_OPCODE_RESULT     0x08
#define CASSANDRA_OPCODE_EXECUTE    0x0A
#define CASSANDRA_OPCODE_BATCH      0x0D

struct cassandra_header {
    __u8 version;
    __u8 flags;
    __s16 stream_id;
    __u8 opcode;
};

static __always_inline
int is_cassandra_request(char *buf, __u64 buf_size, __s16 *stream_id) {
    struct cassandra_header h = {};
    if (buf_size < sizeof(h)) {
        return 0;
    }
    bpf_read(buf, h);
    if (h.version != CASSANDRA_REQUEST_FRAME) {
        return 0;
    }
    if (h.opcode == CASSANDRA_OPCODE_QUERY || h.opcode == CASSANDRA_OPCODE_EXECUTE || h.opcode == CASSANDRA_OPCODE_BATCH) {
        *stream_id = h.stream_id;
        return 1;
    }
    return 0;
}

static __always_inline
int is_cassandra_response(char *buf, __u64 buf_size, __s16 *stream_id, __s32 *status) {
    struct cassandra_header h = {};
    if (buf_size < sizeof(h)) {
        return 0;
    }
    bpf_read(buf, h);
    if (h.version != CASSANDRA_RESPONSE_FRAME) {
        return 0;
    }
    if (h.opcode == CASSANDRA_OPCODE_RESULT) {
        *stream_id = h.stream_id;
        *status = STATUS_OK;
        return 1;
    }
    if (h.opcode == CASSANDRA_OPCODE_ERROR) {
        *stream_id = h.stream_id;
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}

