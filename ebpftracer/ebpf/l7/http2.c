#define HTTP2_CLIENT_INITIATED_STREAM(stream_id) (stream_id & 0x01000000) // big-endian (network byte order) odd number
#define HTTP2_SETTINGS_FRAME 0x4

static __always_inline
int is_client_preface(char *buf, __u64 size, __u8 method) {
    if (method != METHOD_HTTP2_CLIENT_FRAMES || size < 24) {
        return 0;
    }
    char b[5];
    bpf_read(buf, b);
    if (b[0] == 'P' && b[1]=='R' && b[2]=='I' && b[3]==' ' && b[4]=='*') {
        return 1;
    }
    return 0;
}

static __always_inline
int is_server_preface(__u8 frame_type, __u32 stream_id, __u8 method) {
    return method == METHOD_HTTP2_SERVER_FRAMES && frame_type == HTTP2_SETTINGS_FRAME && stream_id == 0;
}

static __always_inline
int looks_like_http2_frame(char *buf, __u64 size, __u8 method) {
    __u32 frame_length;
    bpf_read(buf, frame_length);
    frame_length = bpf_htonl(frame_length) >> 8;
    if (frame_length + 9 > size) {
        return is_client_preface(buf, size, method);
    }
    __u8 frame_type;
    bpf_read(buf+3, frame_type);
    if (frame_type > 0x9) {
        return is_client_preface(buf, size, method);
    }
    __u32 stream_id;
    bpf_read(buf+5, stream_id);
    if (!HTTP2_CLIENT_INITIATED_STREAM(stream_id)) {
        return is_server_preface(frame_type, stream_id, method);
    }
    return 1;
}