// https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
#define MYSQL_COM_QUERY		    3
#define MYSQL_COM_STMT_EXECUTE  23

#define MYSQL_RESPONSE_OK    0x00
#define MYSQL_RESPONSE_EOF   0xfe
#define MYSQL_RESPONSE_ERROR 0xff

static __always_inline
int is_mysql_query(char *buf, int buf_size) {
    if (buf_size < 1) {
        return 0;
    }
    __u8 b[5];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }
    int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    if (length+4 != buf_size || b[3] != 0) { // sequence must be 0
        return 0;
    }
    if (b[4] ==  MYSQL_COM_QUERY || b[4] == MYSQL_COM_STMT_EXECUTE) {
        return 1;
    }
    return 0;
}

static __always_inline
__u32 parse_mysql_status(char *buf, int buf_size) {
    __u8 b[5];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (b[3] < 1) { // sequence must be > 0
        return 0;
    }
    int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    if (length == 1 || b[4] == MYSQL_RESPONSE_OK || b[4] == MYSQL_RESPONSE_EOF) {
        return 200;
    }
    if (b[4] == MYSQL_RESPONSE_ERROR) {
        return 500;
    }
    return 0;
}
