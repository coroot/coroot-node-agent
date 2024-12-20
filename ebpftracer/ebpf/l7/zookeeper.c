// https://github.com/apache/zookeeper/blob/release-3.4.9/src/java/main/org/apache/zookeeper/ZooDefs.java#L28
#define ZK_OP_NOTIFY           0
#define ZK_OP_CREATE_CONTAINER 19
#define ZK_OP_CREATE_TTL       21
#define ZK_OP_CLOSE           -11
#define ZK_OP_SET_AUTH        100
#define ZK_OP_SET_WATCHES     101
#define ZK_OP_ERROR            -1

#define ZK_ERR_OK                   0
#define ZK_ERR_SYSTEM_ERROR        -1
#define ZK_ERR_INVALID_STATE       -9
#define ZK_ERR_RECONFIG_DISABLED -123

struct zk_request_header {
    __be32 length;
    __be32 xid;
    __be32 op_code;
};

struct zk_response_header {
    __be32 length;
	__be32 xid;
	__be64 zxid;
	__be32 err_code;
};

static __always_inline
int is_zk_request(char *buf, __u64 buf_size) {
    struct zk_request_header req = {};

    bpf_read(buf, req);

    if (bpf_ntohl(req.length)+4 != buf_size) {
        return 0;
    }
    __s32 xid = bpf_ntohl(req.xid);
    if (xid < 0 && xid != -1 && xid != -2) {
        return 0;
    }
    __s32 op = bpf_ntohl(req.op_code);
    if (op >= ZK_OP_NOTIFY && op <= ZK_OP_CREATE_CONTAINER) {
        return 1;
    }
    if (op == ZK_OP_CREATE_TTL || op == ZK_OP_CLOSE || op == ZK_OP_SET_AUTH || op == ZK_OP_SET_WATCHES || op == ZK_OP_ERROR) {
        return 1;
    }
    return 0;
}

static __always_inline
int is_zk_response(char *buf, __u64 buf_size, __s32 *status) {
    struct zk_response_header resp = {};
    bpf_read(buf, resp);
    if (bpf_ntohl(resp.length)+4 != buf_size) {
        return 0;
    }
    __s32 xid = bpf_ntohl(resp.xid);
    if (xid < 0 && xid != -1 && xid != -2) {
        return 0;
    }
    *status = bpf_ntohl(resp.err_code);
    if (*status > 0 || *status < ZK_ERR_RECONFIG_DISABLED) {
        return 0;
    }
    return 1;
}
