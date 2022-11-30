// https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec

#define CASSANDRA_REQUEST_FRAME  0x04
#define CASSANDRA_RESPONSE_FRAME 0x84

#define CASSANDRA_OPCODE_ERROR  0x00
#define CASSANDRA_OPCODE_RESULT 0x08

struct cassandra_header {
    __u8 version;
    __u8 flags;
    __s16 stream_id;
    __u8 opcode;
};

static __always_inline
__s16 is_cassandra_request(char *buf, int buf_size) {
    if (buf_size < 1) {
        return -1;
    }
    struct cassandra_header h = {};
    if (bpf_probe_read(&h, sizeof(h), (void *)buf) < 0) {
        return -1;
    }
    if (h.version == CASSANDRA_REQUEST_FRAME && h.stream_id >= 0) {
        return h.stream_id;
    }
    return -1;
}

static __always_inline
__u32 cassandra_status(struct cassandra_header h) {
    if (h.version != CASSANDRA_RESPONSE_FRAME || h.stream_id == -1) {
        return 0;
    }
    if (h.opcode == CASSANDRA_OPCODE_RESULT) {
        return 200;
    }
    if (h.opcode == CASSANDRA_OPCODE_ERROR) {
        return 500;
    }
    return 0;
}

