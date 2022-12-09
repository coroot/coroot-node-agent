// AMQP 0-9-1 Protocol Specification
// https://www.rabbitmq.com/protocol.html

#define RABBITMQ_FRAME_TYPE_METHOD 1
#define RABBITMQ_FRAME_END 0xCE

#define RABBITMQ_CLASS_BASIC 60
#define RABBITMQ_METHOD_PUBLISH 40
#define RABBITMQ_METHOD_DELIVER 60

static __always_inline
int rabbitmq_method_is(char *buf, __u64 buf_size, __u16 expected_method) {
    if (buf_size < 12) {
        return 0;
    }
    __u8 type = 0;
    bpf_read(buf, type);
    if (type != RABBITMQ_FRAME_TYPE_METHOD) {
        return 0;
    }

    __u32 size = 0;
    bpf_read(buf+3, size);
    size = bpf_htonl(size);
    if (7 + size + 1 > buf_size) {
        return 0;
    }
    __u8 end = 0;
    bpf_read(buf+7+size, end);
    if (end != RABBITMQ_FRAME_END) {
        return 0;
    }

    __u16 class = 0;
    bpf_read(buf+7, class);
    if (bpf_htons(class) != RABBITMQ_CLASS_BASIC) {
        return 0;
    }

    __u16 method = 0;
    bpf_read(buf+9, method);
    if (bpf_htons(method) != expected_method) {
        return 0;
    }

    return 1;
}

static __always_inline
int is_rabbitmq_produce(char *buf, __u64 buf_size) {
    return rabbitmq_method_is(buf, buf_size, RABBITMQ_METHOD_PUBLISH);
}

static __always_inline
int is_rabbitmq_consume(char *buf, __u64 buf_size) {
    return rabbitmq_method_is(buf, buf_size, RABBITMQ_METHOD_DELIVER);
}
