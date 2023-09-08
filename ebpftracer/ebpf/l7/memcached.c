// https://github.com/memcached/memcached/blob/master/doc/protocol.txt
static __always_inline
int is_memcached_query(char *buf, __u64 buf_size) {
    if (buf_size < 9) {
        return 0;
    }
    char b[7];
    bpf_read(buf, b);
    char end[2];
    TRUNCATE_PAYLOAD_SIZE(buf_size);
    bpf_read(buf+buf_size-2, end);
    if (end[0] != '\r' || end[1] != '\n') {
        return 0;
    }
    if (b[0] == 's' && b[1] == 'e' && b[2] == 't' && b[3] == ' ') {
        return 1;
    }
    if (b[0] == 'a' && b[1] == 'd' && b[2] == 'd' && b[3] == ' ') {
        return 1;
    }
    if (b[0] == 'c' && b[1] == 'a' && b[2] == 's' && b[3] == ' ') {
        return 1;
    }
    if (b[0] == 'g' && (b[1] == 'a' || b[1] == 'e') && b[2] == 't' && (b[3] == ' ' || b[3] == 's')) { // get/gets/gat/gats
        return 1;
    }
    if (b[0] == 'i' && b[1] == 'n' && b[2] == 'c' && b[3] == 'r' && b[4] == ' ') {
        return 1;
    }
    if (b[0] == 'd' && b[1] == 'e' && b[2] == 'c' && b[3] == 'r' && b[4] == ' ') {
        return 1;
    }
    if (b[0] == 't' && b[1] == 'o' && b[2] == 'u' && b[3] == 'c' && b[4] == 'h' && b[5] == ' ') {
        return 1;
    }
    if (b[0] == 'd' && b[1] == 'e' && b[2] == 'l' && b[3] == 'e' && b[4] == 't' && b[5] == 'e' && b[6] == ' ') {
        return 1;
    }
    if (b[0] == 'a' && b[1] == 'p' && b[2] == 'p' && b[3] == 'e' && b[4] == 'n' && b[5] == 'd' && b[6] == ' ') {
        return 1;
    }
    if (b[0] == 'p' && b[1] == 'r' && b[2] == 'e' && b[3] == 'p' && b[4] == 'e' && b[5] == 'n' && b[6] == 'd') {
        return 1;
    }
    if (b[0] == 'r' && b[1] == 'e' && b[2] == 'p' && b[3] == 'l' && b[4] == 'a' && b[5] == 'c' && b[6] == 'e') {
        return 1;
    }
    return 0;
}

static __always_inline
int is_memcached_response(char *buf, __u64 buf_size, __u32 *status) {
    char r[3];
    bpf_read(buf, r);
    char end[2];
    TRUNCATE_PAYLOAD_SIZE(buf_size);
    bpf_read(buf+buf_size-2, end);
    if (end[0] != '\r' || end[1] != '\n') {
        return 0;
    }
    if (r[0] == 'V' && r[1] == 'A' && r[2] == 'L') { //VALUE
        *status = STATUS_OK;
        return 1;
    }
    if (r[0] == 'S' && r[1] == 'T' && r[2] == 'O') { //STORED
        *status = STATUS_OK;
        return 1;
    }
    if (r[0] == 'D' && r[1] == 'E' && r[2] == 'L') { //DELETED
        *status = STATUS_OK;
        return 1;
    }
    if (r[0] == 'T' && r[1] == 'O' && r[2] == 'C') { //TOUCHED
        *status = STATUS_OK;
        return 1;
    }
    if (r[0] == 'N' && r[1] == 'O' && r[2] == 'T') { //NOT_STORED || NOT_FOUND
        *status = STATUS_OK;
        return 1;
    }
    if (r[0] == 'E' && r[1] == 'X' && r[2] == 'I') { //EXISTS
        *status = STATUS_OK;
        return 1;
    }
    if (r[0] == 'E' && r[1] == 'R' && r[2] == 'R') { //ERROR
        *status = STATUS_FAILED;
        return 1;
    }
    if (r[0] == 'C' && r[1] == 'L' && r[2] == 'I') { //CLIENT_ERROR
        *status = STATUS_FAILED;
        return 1;
    }
    if (r[0] == 'S' && r[1] == 'E' && r[2] == 'R') { //SERVER_ERROR
        *status = STATUS_FAILED;
        return 1;
    }
    if (r[0] >= '0' && r[0] <= '9') { // incr/decr response: <value>\r\n
        *status = STATUS_OK;
        return 1;
    }
    return 0;
}
