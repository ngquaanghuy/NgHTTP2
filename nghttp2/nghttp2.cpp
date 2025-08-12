
#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#define MAKE_NV(NAME, VALUE) { (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE }
struct Connection {
	int fd;
	SSL *ssl;
};
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int, void *user_data) {
	Connection *conn = (Connection*)user_data;
	int ret = SSL_write(conn->ssl, data, length);
	if (ret <= 0) {
		int err = SSL_get_error(conn->ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			return NGHTTP2_ERR_WOULDBLOCK;
		}
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return ret;
}
static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, ssize_t length, int, void *user_data) {
	Connection *conn = (Connection*)user_data;
	int ret = SSL_read(conn->ssl, buf, length);
	if (ret <= 0) {
		int err = SSL_get_error(conn->ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			return NGHTTP2_ERR_WOULDBLOCK;
		}
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return ret;
}
static int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t, void*) {
	if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
		std::cout << std::string((const char*)name, namelen) << ";" << std::string((const char*)value, valuelen) << "\n";
	}
	return 0;
}
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void*) {

	//std::cout.write((const char*)data, len);
	return 0;
}
int requests_done = 0;
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
	std::cout << "Done Stream" << "\n";
	const char *nv[][2] {
		{":method", "GET"},
		{":path", "/"},
		{":scheme", "https"},
		{":authority", "repo.estranged-tech.top"},
		{":user-agent", "nghttp2/1.0"}
	};
	nghttp2_nv headers[5];
	for (int i = 0; i < 5;i++) {
		headers[i].name = (uint8_t*)nv[i][0];
		headers[i].value = (uint8_t*)nv[i][1];
		headers[i].namelen = strlen(nv[i][0]);
		headers[i].valuelen = strlen(nv[i][1]);
		headers[i].flags = NGHTTP2_NV_FLAG_NONE;
	}
	requests_done++;
	std::cout << "Requests finish: " << requests_done << "\n";
	//nghttp2_submit_request(session, nullptr, headers, 5, nullptr, nullptr);
	return 0;
}
int max_requests = 10000;
int requests_send = 0;
int sendRequest(const char* ip, const char* port) {
	SSL_library_init();
	SSL_load_error_strings();
	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	const unsigned char alpn_protos[] = {2, 'h', '2'};
	SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos));

	// TCP CONNECT 
	addrinfo hints{}, *res;
	hints.ai_family  = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo(ip, port, &hints, &res);
	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	connect(fd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	std::cout << "TCP CONNECT" << "\n";

	// TLS HANDSHAKE
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	SSL_set_tlsext_host_name(ssl, ip);
	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	std::cout << "TLS HANDSHAKE" << "\n";

	// NGHTTP2 SETUP
	const char *nv[][2] {
		{":method", "GET"},
		{":path", "/"},
		{":scheme", "https"},
		{":authority", "repo.estranged-tech.top"},
		{":user-agent", "nghttp2/1.0"}
	};
	nghttp2_nv headers[5];
	for (int i = 0; i < 5;i++) {
		headers[i].name = (uint8_t*)nv[i][0];
		headers[i].value = (uint8_t*)nv[i][1];
		headers[i].namelen = strlen(nv[i][0]);
		headers[i].valuelen = strlen(nv[i][1]);
		headers[i].flags = NGHTTP2_NV_FLAG_NONE;
	}
	nghttp2_session_callbacks *callbacks;
	nghttp2_session_callbacks_new(&callbacks);
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);

	nghttp2_session *session;
	Connection conn;
	conn.fd = fd;
	conn.ssl = ssl;
	nghttp2_session_client_new(&session, callbacks, &conn);
	std::cout << "NGHTTP2 SETUP" << "\n";
	//SEND SETTINGS FRAME
	nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);

	// HEADER
	std::cout << "SETTING UP HEADER" "\n";
	nghttp2_submit_request(session, nullptr, headers, 5, nullptr, nullptr);
	std::cout << "SEND REQUEST" << "\n";
	// while events
	while (requests_send < max_requests) {
		//nghttp2_submit_request(session, nullptr, headers, 5, nullptr, nullptr)
		while (requests_send < max_requests)  {
			nghttp2_submit_request(session, nullptr, headers, 5, nullptr, nullptr);
			requests_send++;
			std::cout << "Requests count: " << requests_send << "\n";
		}
		if (nghttp2_session_want_write(session)) {
			nghttp2_session_send(session);
		}
		if (nghttp2_session_want_read(session)) {
			nghttp2_session_recv(session);
		}
	}
	std::cout << "DONE " << "\n";
	nghttp2_session_del(session);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(fd);
	SSL_CTX_free(ctx);
	return 1;
}

int main() {
	addrinfo hints{}, *res;
	hints.ai_family = AF_UNSPEC;
	std::cout << getaddrinfo("graph.vshield.pro", "443", &hints, &res) << "\n";
	while (true) {
		sendRequest("repo.estranged-tech.top", "443");
	}
	return 0;
}
