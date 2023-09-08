// https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
#define MYSQL_COM_QUERY		    3
#define MYSQL_COM_STMT_PREPARE  0x16
#define MYSQL_COM_STMT_EXECUTE  0x17
#define MYSQL_COM_STMT_CLOSE    0x19

#define MYSQL_RESPONSE_OK    0x00
#define MYSQL_RESPONSE_EOF   0xfe
#define MYSQL_RESPONSE_ERROR 0xff


static __always_inline
int is_mysql_query(char *buf, __u64 buf_size, __u8 *request_type) {
    if (buf_size < 5) {
        return 0;
    }
    __u8 b[5];
    bpf_read(buf, b);
    int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    if (length+4 != buf_size || b[3] != 0) { // sequence must be 0
        return 0;
    }
    if (b[4] ==  MYSQL_COM_QUERY || b[4] == MYSQL_COM_STMT_EXECUTE) {
        return 1;
    }
    if (b[4] == MYSQL_COM_STMT_CLOSE) {
        *request_type = MYSQL_COM_STMT_CLOSE;
        return 1;
    }
    if (b[4] == MYSQL_COM_STMT_PREPARE) {
        *request_type = MYSQL_COM_STMT_PREPARE;
        return 1;
    }
    return 0;
}

static __always_inline
int is_mysql_response(char *buf, __u64 buf_size, __u8 request_type, __u32 *statement_id, __u32 *status) {
    __u8 b[5];
    bpf_read(buf, b);
    if (b[3] < 1) { // sequence must be > 0
        return 0;
    }
    int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    if (length == 1 || b[4] == MYSQL_RESPONSE_EOF) {
        *status = STATUS_OK;
        return 1;
    }
    if (b[4] == MYSQL_RESPONSE_OK ) {
        if (request_type == MYSQL_COM_STMT_PREPARE) {
            bpf_read(buf+5, *statement_id);
        }
        *status = STATUS_OK;
        return 1;
    }
    if (b[4] == MYSQL_RESPONSE_ERROR) {
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}
