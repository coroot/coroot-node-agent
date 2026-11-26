// A native addon that does its own TLS: an SSL with a socket BIO, as in pg-native or a database driver.
// It is not linked to libssl, so its SSL_* calls bind to the OpenSSL that the node executable exports.
#include <netdb.h>
#include <node_api.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static SSL *ssl;

static napi_value Open(napi_env env, napi_callback_info info) {
    size_t argc = 2, n;
    napi_value argv[2], res;
    char host[256], port[16];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    napi_get_value_string_utf8(env, argv[0], host, sizeof(host), &n);
    napi_get_value_string_utf8(env, argv[1], port, sizeof(port), &n);
    napi_get_boolean(env, 0, &res);
    struct addrinfo *ai;
    if (getaddrinfo(host, port, NULL, &ai) != 0) {
        return res;
    }
    int fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) == 1) {
            napi_get_boolean(env, 1, &res);
        }
    } else {
        close(fd);
    }
    freeaddrinfo(ai);
    return res;
}

static napi_value Request(napi_env env, napi_callback_info info) {
    char buf[512] = "error";
    const char *req = "GET /addon HTTP/1.1\r\nHost: nodetest\r\nConnection: keep-alive\r\n\r\n";
    if (ssl && SSL_write(ssl, req, strlen(req)) > 0) {
        int r = SSL_read(ssl, buf, sizeof(buf) - 1);
        buf[r > 0 ? r : 0] = 0;
        char *eol = strstr(buf, "\r\n");
        if (eol) {
            *eol = 0;
        }
    }
    napi_value res;
    napi_create_string_utf8(env, buf, NAPI_AUTO_LENGTH, &res);
    return res;
}

static napi_value Close(napi_env env, napi_callback_info info) {
    if (ssl) {
        int fd = SSL_get_fd(ssl);
        SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        ssl = NULL;
    }
    napi_value res;
    napi_get_undefined(env, &res);
    return res;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor props[] = {
        {"open", NULL, Open, NULL, NULL, NULL, napi_default, NULL},
        {"request", NULL, Request, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, Close, NULL, NULL, NULL, napi_default, NULL},
    };
    napi_define_properties(env, exports, 3, props);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
