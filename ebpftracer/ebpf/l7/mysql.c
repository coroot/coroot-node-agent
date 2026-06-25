// https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
#define MYSQL_COM_QUERY		    3
#define MYSQL_COM_STMT_PREPARE  0x16
#define MYSQL_COM_STMT_EXECUTE  0x17
#define MYSQL_COM_STMT_CLOSE    0x19

#define MYSQL_RESPONSE_OK    0x00
#define MYSQL_RESPONSE_EOF   0xfe
#define MYSQL_RESPONSE_ERROR 0xff


static __always_inline
int is_mysql_partial_header(char *buf, __u64 buf_size, __u32 *payload_length) {
    if (buf_size != 4) {
        return 0;
    }
    __u8 b[4];
    bpf_read(buf, b);
    if (b[3] != 0) { // sequence must be 0
        return 0;
    }
    int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    if (length < 1) {
        return 0;
    }
    *payload_length = (__u32)length;
    return 1;
}

static __always_inline
int is_mysql_query(char *buf, __u64 buf_size, __u8 *request_type, struct l7_request *pending) {
    if (buf_size < 1) {
        return 0;
    }
    __u8 reqType;
    if (pending && pending->protocol == PROTOCOL_UNKNOWN && pending->partial == 1) {
        int length = pending->payload_size;
        if (length != buf_size) {
            return 0;
        }
        bpf_read(buf, reqType);
    } else {
        if (buf_size < 5) {
            return 0;
        }
        __u8 b[5];
        bpf_read(buf, b);
        int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
        if (length+4 != buf_size || b[3] != 0) { // sequence must be 0
            return 0;
        }
        reqType = b[4];
    }

    if (reqType == MYSQL_COM_QUERY || reqType == MYSQL_COM_STMT_EXECUTE) {
        return 1;
    }
    if (reqType == MYSQL_COM_STMT_CLOSE) {
        *request_type = MYSQL_COM_STMT_CLOSE;
        return 1;
    }
    if (reqType == MYSQL_COM_STMT_PREPARE) {
        *request_type = MYSQL_COM_STMT_PREPARE;
        return 1;
    }
    return 0;
}

static __always_inline
int is_mysql_response(char *buf, __u64 buf_size, __u8 request_type, __u32 *statement_id, __s32 *status) {
    if (buf_size < 4) {
        return 0;
    }
    __u8 b[4];
    bpf_read(buf, b);
    if (b[3] < 1) { // sequence must be > 0
        return 0;
    }
    int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    if (length < 1) {
        return 0;
    }
    if (buf_size < 5) {
        *status = STATUS_OK;
        return 1;
    }
    __u8 type_byte;
    bpf_read(buf+4, type_byte);
    if (length == 1 || type_byte == MYSQL_RESPONSE_EOF) {
        *status = STATUS_OK;
        return 1;
    }
    if (type_byte == MYSQL_RESPONSE_OK) {
        if (request_type == MYSQL_COM_STMT_PREPARE && buf_size >= 9) {
            bpf_read(buf+5, *statement_id);
        }
        *status = STATUS_OK;
        return 1;
    }
    if (type_byte == MYSQL_RESPONSE_ERROR) {
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}
