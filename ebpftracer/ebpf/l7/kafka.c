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
int is_kafka_request(char *buf, __u64 buf_size, __s32 *request_id) {
    struct kafka_request_header h = {};
    if (buf_size < sizeof(h)) {
        return 0;
    }
    bpf_read(buf, h);

    h.length = bpf_htonl(h.length);
    if (h.length+4 != buf_size) {
        return 0;
    }
    h.api_key = bpf_htons(h.api_key);
//    h.api_version = bpf_htons(h.api_version);
    h.correlation_id = bpf_htonl(h.correlation_id);
    if (h.correlation_id > 0 && (h.api_key >= 0 && h.api_key <= 67)) {
        *request_id = h.correlation_id;
        return 1;
    }
    return 0;
}

static __always_inline
int is_kafka_response(char *buf, __s32 request_id) {
    struct kafka_response_header h = {};
    bpf_read(buf, h);
    if (bpf_htonl(h.correlation_id) == request_id) {
        return 1;
    }
    return 0;
}


