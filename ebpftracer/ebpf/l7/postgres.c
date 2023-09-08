// Postgres wire protocol
// https://www.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf
// https://www.postgresql.org/docs/current/protocol-message-formats.html

#define POSTGRES_FRAME_SIMPLE_QUERY 'Q'
#define POSTGRES_FRAME_PARSE 'P'
#define POSTGRES_FRAME_CLOSE 'C'

static __always_inline
int is_postgres_query(char *buf, __u64 buf_size, __u8 *request_type) {
    char f_cmd;
    int f_length;
    if (buf_size < sizeof(f_cmd)+sizeof(f_length)) {
        return 0;
    }
    bpf_read(buf, f_cmd);
    bpf_read(buf+1, f_length);
    f_length = bpf_htonl(f_length);

    *request_type = f_cmd;
    if ((f_cmd == POSTGRES_FRAME_SIMPLE_QUERY || f_cmd == POSTGRES_FRAME_CLOSE) && f_length+1 == buf_size) {
        return 1;
    }
    char sync[5];
    TRUNCATE_PAYLOAD_SIZE(buf_size);
    bpf_read(buf+buf_size-5, sync);
    if (sync[0] == 'S' && sync[1] == 0 && sync[2] == 0 && sync[3] == 0 && sync[4] == 4) {
        return 1;
    }
    return 0;
}

static __always_inline
int is_postgres_response(char *buf, __u64 buf_size, __u32 *status) {
    char cmd;
    int length;
    bpf_read(buf, cmd);
    bpf_read(buf+1, length);
    length = bpf_htonl(length);

    if (length+1 > buf_size) {
        return 0;
    }
    if ((cmd == '1' || cmd == '2') && length == 4 && buf_size >= 10) {
        bpf_read(buf+5, cmd);
        bpf_read(buf+5+1, length);
    }
    if (cmd == 'E') {
        *status = STATUS_FAILED;
        return 1;
    }
    if (cmd == 't' || cmd == 'T' || cmd == 'D' || cmd == 'C') {
        *status = STATUS_OK;
        return 1;
    }
    return 0;
}
