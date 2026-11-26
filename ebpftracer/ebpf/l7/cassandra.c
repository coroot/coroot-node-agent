// https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec
// https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v5.spec

#define CASSANDRA_V4 0x04
#define CASSANDRA_V5 0x05
#define CASSANDRA_RESPONSE_FLAG 0x80

#define CASSANDRA_V5_SEGMENT_HEADER_SIZE 6
#define CASSANDRA_V5_LZ4_SEGMENT_HEADER_SIZE 8
#define CASSANDRA_ENVELOPE_HEADER_SIZE 9

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
int cassandra_header_matches(struct cassandra_header *h, __u8 version) {
    if (h->version != version) {
        return 0;
    }
    if (version & CASSANDRA_RESPONSE_FLAG) {
        return h->opcode == CASSANDRA_OPCODE_RESULT || h->opcode == CASSANDRA_OPCODE_ERROR;
    }
    return h->opcode == CASSANDRA_OPCODE_QUERY || h->opcode == CASSANDRA_OPCODE_EXECUTE || h->opcode == CASSANDRA_OPCODE_BATCH;
}

static __always_inline
int cassandra_read_lz4_header(char *buf, struct cassandra_header *h) {
    __u8 b[8];
    bpf_read(buf, b);
    __u8 literals = b[0] >> 4;
    if (literals >= 5) {
        __u64 offset = 1;
        if (literals == 15) {
            offset++;
            if (b[1] == 255) {
                offset++;
                if (b[2] == 255) {
                    return 0;
                }
            }
        }
        bpf_read(buf + offset, *h);
        return 1;
    }
    if (literals == 0) {
        return 0;
    }
    __u8 lo = 0, hi = 0;
    #pragma unroll
    for (int i = 2; i <= 6; i++) {
        if (i == literals + 1) {
            lo = b[i];
        }
        if (i == literals + 2) {
            hi = b[i];
        }
    }
    __u32 match_offset = (__u32)lo | (__u32)hi << 8;
    if (match_offset == 0 || match_offset > literals) {
        return 0;
    }
    __u8 out[5] = {};
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (i < literals) {
            out[i] = b[i + 1];
            continue;
        }
        #pragma unroll
        for (int j = 0; j < i; j++) {
            if (j + match_offset == i) {
                out[i] = out[j];
            }
        }
    }
    h->version = out[0];
    h->flags = out[1];
    h->stream_id = (__s16)((__u16)out[2] | (__u16)out[3] << 8);
    h->opcode = out[4];
    return 1;
}

static __always_inline
int cassandra_read_header(char *buf, __u64 buf_size, __u8 direction, struct cassandra_header *h) {
    if (buf_size < sizeof(*h)) {
        return 0;
    }
    bpf_read(buf, *h);
    if (cassandra_header_matches(h, CASSANDRA_V4 | direction)) {
        return 1;
    }

    __u8 version = CASSANDRA_V5 | direction;
    if (buf_size < CASSANDRA_V5_SEGMENT_HEADER_SIZE + CASSANDRA_ENVELOPE_HEADER_SIZE) {
        return 0;
    }
    __u8 s[5];
    bpf_read(buf, s);
    __u32 length = (__u32)s[0] | (__u32)s[1] << 8 | (__u32)(s[2] & 1) << 16;
    if (length >= CASSANDRA_ENVELOPE_HEADER_SIZE && s[2] >> 2 == 0) {
        bpf_read(buf + CASSANDRA_V5_SEGMENT_HEADER_SIZE, *h);
        if (cassandra_header_matches(h, version)) {
            return 1;
        }
    }

    if (buf_size < CASSANDRA_V5_LZ4_SEGMENT_HEADER_SIZE + CASSANDRA_ENVELOPE_HEADER_SIZE) {
        return 0;
    }
    if (s[4] >> 3) {
        return 0;
    }
    __u32 uncompressed_length = (__u32)s[2] >> 1 | (__u32)s[3] << 7 | (__u32)(s[4] & 3) << 15;
    if (uncompressed_length == 0) {
        bpf_read(buf + CASSANDRA_V5_LZ4_SEGMENT_HEADER_SIZE, *h);
        return cassandra_header_matches(h, version);
    }
    if (uncompressed_length < CASSANDRA_ENVELOPE_HEADER_SIZE) {
        return 0;
    }
    if (!cassandra_read_lz4_header(buf + CASSANDRA_V5_LZ4_SEGMENT_HEADER_SIZE, h)) {
        return 0;
    }
    return cassandra_header_matches(h, version);
}

static __always_inline
int is_cassandra_request(char *buf, __u64 buf_size, __s16 *stream_id) {
    struct cassandra_header h = {};
    if (!cassandra_read_header(buf, buf_size, 0, &h)) {
        return 0;
    }
    *stream_id = h.stream_id;
    return 1;
}

static __always_inline
int is_cassandra_response(char *buf, __u64 buf_size, __s16 *stream_id, __s32 *status) {
    struct cassandra_header h = {};
    if (!cassandra_read_header(buf, buf_size, CASSANDRA_RESPONSE_FLAG, &h)) {
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

