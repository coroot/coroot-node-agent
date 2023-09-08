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
int is_mongo_query(char *buf, __u64 buf_size) {
    struct mongo_header h = {};
    if (buf_size < sizeof(h)) {
        return 0;
    }
    bpf_read(buf, h);
    if (h.response_to == 0 && (h.op_code == MONGO_OP_MSG || h.op_code == MONGO_OP_COMPRESSED)) {
        return 1;
    }
    return 0;
}

static __always_inline
int is_mongo_response(char *buf, __u64 buf_size, __u8 partial) {
    if (partial == 0 && buf_size == 4) { //partial read
        return 2;
    }
    struct mongo_header h = {};
    if (partial) {
        bpf_read(buf+4, h.response_to);
        bpf_read(buf+8, h.op_code);
    } else {
        bpf_read(buf, h);
    }
    if (h.response_to == 0) {
        return 0;
    }
    if (h.op_code == MONGO_OP_MSG || h.op_code == MONGO_OP_COMPRESSED) {
        return 1;
    }
    return 0;
}


