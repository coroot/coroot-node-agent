// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/

#define MONGO_OP_COMPRESSED 2012
#define MONGO_OP_MSG        2013

struct mongo_header {
    __s32 length;
    __s32 request_id;
    __s32 response_to;
    __s32 op_code;
};

static __always_inline
int is_mongo_query(char *buf, int buf_size) {
    if (buf_size < 1) {
        return 0;
    }
    struct mongo_header h = {};
    if (bpf_probe_read(&h, sizeof(h), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (h.response_to == 0 && (h.op_code == MONGO_OP_MSG || h.op_code == MONGO_OP_COMPRESSED)) {
        return 1;
    }
    return 0;
}

static __always_inline
__u32 parse_mongo_status(char *buf, int buf_size, __u8 partial) {
    if (partial == 0 && buf_size == 4) { //partial read
        return 1;
    }
    struct mongo_header h = {};
    if (partial) {
        if (bpf_probe_read(&h.response_to, sizeof(h.response_to), (void *)((char *)buf+4)) < 0) {
            return 0;
        }
        if (bpf_probe_read(&h.op_code, sizeof(h.op_code), (void *)((char *)buf+8)) < 0) {
            return 0;
        }
    } else {
        if (bpf_probe_read(&h, sizeof(h), (void *)((char *)buf)) < 0) {
            return 0;
        }
    }
    if (h.response_to == 0) {
        return 0;
    }
    if (h.op_code == MONGO_OP_MSG || h.op_code == MONGO_OP_COMPRESSED) {
        return 200;
    }
    return 0;
}


