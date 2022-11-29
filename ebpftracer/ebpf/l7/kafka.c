// https://kafka.apache.org/protocol.html

struct kafka_request_header {
    __s32 length;
    __s16 api_key;
    __s16 api_version;
    __s32 correlation_id;
};

struct kafka_response_header {
    __s32 length;
    __s32 correlation_id;
};

static __always_inline
__s32 is_kafka_request(char *buf, int buf_size) {
    if (buf_size < 1) {
        return 0;
    }
    struct kafka_request_header h = {};
    if (bpf_probe_read(&h, sizeof(h), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (h.correlation_id > 0 && (h.api_key >= 0 && h.api_key <= 67)) {
        return h.correlation_id;
    }
    return 0;
}

static __always_inline
__u32 parse_kafka_status(__s32 request_id, char *buf, int buf_size, __u8 partial) {
    struct kafka_response_header h = {};
    if (bpf_probe_read(&h, sizeof(h), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (h.correlation_id == request_id) {
        return 200;
    }
    return 0;
}


