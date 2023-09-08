// https://docs.nats.io/reference/reference-protocols/nats-protocol

static __always_inline
int nats_method(char *buf, __u64 buf_size) {
    if (buf_size < 7) {
        return 0;
    }
    char b[5];
    bpf_read(buf, b);
    char end[2];
    TRUNCATE_PAYLOAD_SIZE(buf_size);
    bpf_read(buf+buf_size-2, end);
    if (end[0] != '\r' || end[1] != '\n') {
        return 0;
    }
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'B' && (b[3] == ' ' || b[3] == '\t')) {
        return METHOD_PRODUCE;
    }
    if (b[0] == 'H' && b[1] == 'P' && b[2] == 'U' && b[3] == 'B' && (b[4] == ' ' || b[4] == '\t')) {
        return METHOD_PRODUCE;
    }
    if (b[0] == 'M' && b[1] == 'S' && b[2] == 'G' && (b[3] == ' ' || b[3] == '\t')) {
        return METHOD_CONSUME;
    }
    if (b[0] == 'H' && b[1] == 'M' && b[2] == 'S' && b[3] == 'G' && (b[4] == ' ' || b[4] == '\t')) {
        return METHOD_CONSUME;
    }
    return 0;
}
