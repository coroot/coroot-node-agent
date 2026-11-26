#include <jni.h>

#define MAX_PAYLOAD_SIZE 1024

static __thread char tls_buf[MAX_PAYLOAD_SIZE];

int coroot_java_tls_write_enter(const char *buf, int len) {
    asm volatile("" ::: "memory");
    return len;
}

int coroot_java_tls_read_exit(const char *buf, int len) {
    asm volatile("" ::: "memory");
    return len;
}

struct engine_io {
    unsigned long long engine;
    unsigned long long record_tag;
    const char *buf;
    long long size;
};

int coroot_java_tls_engine_write(const struct engine_io *io) {
    asm volatile("" ::: "memory");
    return 0;
}

int coroot_java_tls_engine_read(const struct engine_io *io) {
    asm volatile("" ::: "memory");
    return 0;
}

static const char *copy_to_tls_buf(JNIEnv *env, jbyteArray data, jint offset, jint length) {
    if (length <= 0) {
        return tls_buf;
    }
    jint n = length < MAX_PAYLOAD_SIZE ? length : MAX_PAYLOAD_SIZE;
    (*env)->GetByteArrayRegion(env, data, offset, n, (jbyte *)tls_buf);
    if ((*env)->ExceptionCheck(env)) {
        return 0;
    }
    return tls_buf;
}

static const char *direct_address(JNIEnv *env, jobject buffer, jint offset) {
    const char *addr = (const char *)(*env)->GetDirectBufferAddress(env, buffer);
    return addr ? addr + offset : 0;
}

JNIEXPORT void JNICALL Java_io_coroot_agent_NativeBridge_tlsWriteEnter(
    JNIEnv *env, jclass cls, jbyteArray data, jint offset, jint length)
{
    jint n = length < MAX_PAYLOAD_SIZE ? length : MAX_PAYLOAD_SIZE;
    (*env)->GetByteArrayRegion(env, data, offset, n, (jbyte *)tls_buf);
    coroot_java_tls_write_enter(tls_buf, length);
}

JNIEXPORT void JNICALL Java_io_coroot_agent_NativeBridge_tlsReadExit(
    JNIEnv *env, jclass cls, jbyteArray data, jint offset, jint length)
{
    jint n = length < MAX_PAYLOAD_SIZE ? length : MAX_PAYLOAD_SIZE;
    (*env)->GetByteArrayRegion(env, data, offset, n, (jbyte *)tls_buf);
    coroot_java_tls_read_exit(tls_buf, length);
}

JNIEXPORT void JNICALL Java_io_coroot_agent_NativeBridge_tlsEngineWrite(
    JNIEnv *env, jclass cls, jint engine, jbyteArray data, jint offset, jint length)
{
    struct engine_io io = {.engine = (unsigned int)engine, .size = length};
    io.buf = copy_to_tls_buf(env, data, offset, length);
    if (io.buf) {
        coroot_java_tls_engine_write(&io);
    }
}

JNIEXPORT void JNICALL Java_io_coroot_agent_NativeBridge_tlsEngineWriteDirect(
    JNIEnv *env, jclass cls, jint engine, jobject data, jint offset, jint length)
{
    struct engine_io io = {.engine = (unsigned int)engine, .size = length};
    io.buf = direct_address(env, data, offset);
    if (io.buf) {
        coroot_java_tls_engine_write(&io);
    }
}

JNIEXPORT void JNICALL Java_io_coroot_agent_NativeBridge_tlsEngineRead(
    JNIEnv *env, jclass cls, jint engine, jlong tag, jbyteArray data, jint offset, jint length)
{
    struct engine_io io = {.engine = (unsigned int)engine, .record_tag = tag, .size = length};
    io.buf = copy_to_tls_buf(env, data, offset, length);
    if (io.buf) {
        coroot_java_tls_engine_read(&io);
    }
}

JNIEXPORT void JNICALL Java_io_coroot_agent_NativeBridge_tlsEngineReadDirect(
    JNIEnv *env, jclass cls, jint engine, jlong tag, jobject data, jint offset, jint length)
{
    struct engine_io io = {.engine = (unsigned int)engine, .record_tag = tag, .size = length};
    io.buf = direct_address(env, data, offset);
    if (io.buf) {
        coroot_java_tls_engine_read(&io);
    }
}
