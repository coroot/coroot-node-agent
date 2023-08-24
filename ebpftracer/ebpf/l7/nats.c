// https://docs.nats.io/reference/reference-protocols/nats-protocol

static __always_inline
int nats_method(char *buf, __u64 buf_size) {
    if (buf_size < 7) {
        return 0;
    }
    char b[5];
    char end[2];
    if (bpf_probe_read(&b, sizeof(b), (void *)buf) < 0) {
        return 0;
    }
    if (bpf_probe_read(&end, sizeof(end), (void *)(buf+buf_size-2)) < 0) {
        return 0;
    }
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
