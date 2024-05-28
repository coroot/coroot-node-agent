#define DNS_QR_RESPONSE 0b10000000
#define DNS_OPCODE 0b01111000
#define DNS_Z 0b11110000
#define DNS_RCODE 0b00001111

struct dns_header {
    __s16 id;
    __u8 bits0;
    __u8 bits1;
    __s16 qdcount;
};

static __always_inline
int is_dns_request(char *buf, __u64 buf_size, __s16 *stream_id) {
    struct dns_header h = {};
    if (buf_size < sizeof(h)) {
        return 0;
    }
    bpf_read(buf, h);
    if (h.bits0 & DNS_QR_RESPONSE) {
        return 0;
    }
    if (h.bits0 & DNS_OPCODE) {
       return 0;
    }
    h.qdcount = bpf_ntohs(h.qdcount);

    if (h.qdcount != 1) {
        return 0;
    }
    *stream_id = h.id;
    return 1;
}

static __always_inline
int is_dns_response(char *buf, __u64 buf_size, __s16 *stream_id, __u32 *status) {
    struct dns_header h = {};
    if (buf_size < sizeof(h)) {
        return 0;
    }
    bpf_read(buf, h);
    if (!(h.bits0 & DNS_QR_RESPONSE)) {
        return 0;
    }
    if (h.bits0 & DNS_OPCODE) {
       return 0;
    }
    if ((h.bits1 & DNS_Z)) {
        return 0;
    }
    h.qdcount = bpf_ntohs(h.qdcount);
    if (h.qdcount != 1) {
        return 0;
    }
    *status = h.bits1 & DNS_RCODE;
    *stream_id = h.id;
    return 1;
}
