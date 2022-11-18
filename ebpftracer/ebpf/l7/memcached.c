// https://github.com/memcached/memcached/blob/master/doc/protocol.txt
static __always_inline
int is_memcached_query(char *buf, int buf_size) {
    if (buf_size < 1) {
        return 0;
    }
    char b[7];
    char end[2];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (bpf_probe_read(&end, sizeof(end), (void *)((char *)buf+buf_size-2)) < 0) {
        return 0;
    }
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
__u32 parse_memcached_status(char *buf, int buf_size) {
    char r[3];
    char end[2];
    if (bpf_probe_read(&r, sizeof(r), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (bpf_probe_read(&end, sizeof(end), (void *)((char *)buf+buf_size-2)) < 0) {
        return 0;
    }
    if (end[0] != '\r' || end[1] != '\n') {
        return 0;
    }
    if (r[0] == 'V' && r[1] == 'A' && r[2] == 'L') { //VALUE
        return 200;
    }
    if (r[0] == 'S' && r[1] == 'T' && r[2] == 'O') { //STORED
        return 200;
    }
    if (r[0] == 'D' && r[1] == 'E' && r[2] == 'L') { //DELETED
        return 200;
    }
    if (r[0] == 'T' && r[1] == 'O' && r[2] == 'C') { //TOUCHED
        return 200;
    }
    if (r[0] == 'N' && r[1] == 'O' && r[2] == 'T') { //NOT_STORED || NOT_FOUND
        return 200;
    }
    if (r[0] == 'E' && r[1] == 'X' && r[2] == 'I') { //EXISTS
        return 200;
    }
    if (r[0] == 'E' && r[1] == 'R' && r[2] == 'R') { //ERROR
        return 500;
    }
    if (r[0] == 'C' && r[1] == 'L' && r[2] == 'I') { //CLIENT_ERROR
        return 500;
    }
    if (r[0] == 'S' && r[1] == 'E' && r[2] == 'R') { //SERVER_ERROR
        return 500;
    }
    if (r[0] >= '0' && r[0] <= '9') { // incr/decr response: <value>\r\n
        return 200;
    }
    return 0;
}
