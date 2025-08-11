#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <iostream>

struct Connection {
    SSL *ssl;
    int fd;
    nghttp2_session *session;
    const char *host;
};

static int on_data_chunk_recv(nghttp2_session *, uint8_t, int32_t, const uint8_t *data,
                              size_t len, void *) {
    std::string s(reinterpret_cast<const char *>(data), len);
    std::cout << s;
    return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t, uint32_t, void *user_data) {
    Connection *conn = (Connection *)user_data;

    // Khi stream đóng, tạo request mới để duy trì tốc độ
    nghttp2_nv nva[5];
    nva[0] = {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE};
    nva[1] = {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE};
    nva[2] = {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE};
    nva[3] = {(uint8_t *)":authority", (uint8_t *)conn->host, 10,
              (uint16_t)strlen(conn->host), NGHTTP2_NV_FLAG_NONE};
    nva[4] = {(uint8_t *)":user-agent", (uint8_t *)"nghttp2-client", 11, 14,
              NGHTTP2_NV_FLAG_NONE};

    nghttp2_submit_request(session, nullptr, nva, 5, nullptr, nullptr);
    return 0;
}

static ssize_t send_callback(nghttp2_session *, const uint8_t *data, size_t length,
                             int, void *user_data) {
    Connection *conn = (Connection *)user_data;
    int rv = SSL_write(conn->ssl, data, (int)length);
    if (rv <= 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    return rv;
}

static ssize_t recv_callback(nghttp2_session *, uint8_t *buf, size_t length,
                             int, void *user_data) {
    Connection *conn = (Connection *)user_data;
    int rv = SSL_read(conn->ssl, buf, (int)length);
    if (rv <= 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    return rv;
}

static int handshake_tls(Connection *conn) {
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return -1;

    SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2", 3);

    struct hostent *h = gethostbyname(conn->host);
    if (!h) return -1;
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    memcpy(&addr.sin_addr, h->h_addr, h->h_length);
    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return -1;

    conn->ssl = SSL_new(ctx);
    SSL_set_fd(conn->ssl, conn->fd);
    if (SSL_connect(conn->ssl) <= 0) return -1;
    return 0;
}

int main() {
    Connection conn{};
    conn.host = "repo.estranged-tech.top";

    if (handshake_tls(&conn) != 0) {
        std::cerr << "TLS handshake failed\n";
        return -1;
    }

    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close);

    nghttp2_session_client_new(&conn.session, callbacks, &conn);
    nghttp2_session_callbacks_del(callbacks);

    // Gửi request ban đầu
    for (int i = 0; i < 50; i++) { // 50 stream song song ban đầu
        nghttp2_nv nva[5];
        nva[0] = {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE};
        nva[1] = {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE};
        nva[2] = {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE};
        nva[3] = {(uint8_t *)":authority", (uint8_t *)conn.host, 10,
                  (uint16_t)strlen(conn.host), NGHTTP2_NV_FLAG_NONE};
        nva[4] = {(uint8_t *)":user-agent", (uint8_t *)"nghttp2-client", 11, 14,
                  NGHTTP2_NV_FLAG_NONE};
        nghttp2_submit_request(conn.session, nullptr, nva, 5, nullptr, nullptr);
    }

    auto last = std::chrono::steady_clock::now();
    int sent_this_sec = 0;
    const int target_rps = 200;

    while (true) {
        nghttp2_session_send(conn.session);
        nghttp2_session_recv(conn.session);

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last).count() >= 1) {
            sent_this_sec = 0;
            last = now;
        }

        if (sent_this_sec < target_rps) {
            nghttp2_nv nva[5];
            nva[0] = {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE};
            nva[1] = {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE};
            nva[2] = {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE};
            nva[3] = {(uint8_t *)":authority", (uint8_t *)conn.host, 10,
                      (uint16_t)strlen(conn.host), NGHTTP2_NV_FLAG_NONE};
            nva[4] = {(uint8_t *)":user-agent", (uint8_t *)"nghttp2-client", 11, 14,
                      NGHTTP2_NV_FLAG_NONE};
            nghttp2_submit_request(conn.session, nullptr, nva, 5, nullptr, nullptr);
            sent_this_sec++;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    close(conn.fd);
    SSL_free(conn.ssl);
    nghttp2_session_del(conn.session);
    return 0;
}
