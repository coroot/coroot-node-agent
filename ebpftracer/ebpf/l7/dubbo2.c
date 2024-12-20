// https://cn.dubbo.apache.org/zh-cn/overview/reference/protocols/tcp/
// https://github.com/apache/dubbo
#define DUBBO_HEADER_LENGTH 16
#define DUBBO_MAGIC_HIGH 0xda
#define DUBBO_MAGIC_LOW 0xbb

#define DUBBO_SERIALMASK 0x1f
#define DUBBO_FLAG_REQUEST 0x80
#define DUBBO_TWO_WAY 0x40
#define DUBBO_HEARTBEAT_EVENT 0x20

#define DUBBO_RESPONSE_OK 20
#define DUBBO_RESPONSE_CLIENT_TIMEOUT 30
#define DUBBO_RESPONSE_SERVER_TIMEOUT 31
#define DUBBO_RESPONSE_BAD_REQUEST 40
#define DUBBO_RESPONSE_BAD_RESPONSE 50
#define DUBBO_RESPONSE_SERVICE_NOT_FOUND 60
#define DUBBO_RESPONSE_SERVICE_ERROR 70
#define DUBBO_RESPONSE_SERVER_ERROR 80
#define DUBBO_RESPONSE_CLIENT_ERROR 90
#define DUBBO_RESPONSE_SERVER_THREADPOOL_EXHAUSTED_ERROR 100

static __always_inline
int is_dubbo2_request(char *buf, __u64 buf_size) {
    if (buf_size < DUBBO_HEADER_LENGTH) {
        return 0;
    }
    __u8 b[16];
    bpf_read(buf, b);
    if (b[0] != DUBBO_MAGIC_HIGH || b[1] != DUBBO_MAGIC_LOW) {
        return 0;
    }

    if ((b[2] & DUBBO_SERIALMASK) == 0 || (b[2] & DUBBO_FLAG_REQUEST) == 0 || (b[2] & DUBBO_TWO_WAY) == 0 || (b[2] & DUBBO_HEARTBEAT_EVENT) != 0) {
        return 0;
    }
    
    return 1;
}


static __always_inline
int is_dubbo2_response(char *buf, __s32 *status) {
    __u8 b[16];
    bpf_read(buf, b);
    if (b[0] != DUBBO_MAGIC_HIGH || b[1] != DUBBO_MAGIC_LOW) {
        return 0;
    }

    if ((b[2] & DUBBO_SERIALMASK) == 0 || (b[2] & DUBBO_FLAG_REQUEST) != 0 || (b[2] & DUBBO_HEARTBEAT_EVENT) != 0) {
        return 0;
    }

    if (b[3] == DUBBO_RESPONSE_OK) {
        *status = STATUS_OK;
        return 1;
    } else if (b[3] == DUBBO_RESPONSE_CLIENT_TIMEOUT || b[3] == DUBBO_RESPONSE_SERVER_TIMEOUT) {
        *status = STATUS_FAILED;
        return 1;
    } else if (b[3] == DUBBO_RESPONSE_BAD_REQUEST || b[3] == DUBBO_RESPONSE_CLIENT_ERROR || b[3] == DUBBO_RESPONSE_SERVICE_NOT_FOUND) {
        *status = STATUS_FAILED;
        return 1;
    } else if (b[3] == DUBBO_RESPONSE_BAD_RESPONSE || b[3] == DUBBO_RESPONSE_SERVICE_ERROR || b[3] == DUBBO_RESPONSE_SERVER_ERROR || b[3] == DUBBO_RESPONSE_SERVER_THREADPOOL_EXHAUSTED_ERROR) {
        *status = STATUS_FAILED;
        return 1;
    } else {
        *status = STATUS_UNKNOWN;
        return 1;
    }
    return 0;
}
