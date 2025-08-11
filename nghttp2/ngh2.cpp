#include <iostream>
#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>

struct Connection {
	int fd;
	SSL *ssl;
};
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
	Connection *conn = (Connection)*user_data;
	int ret = SSL_write(conn->ssl, data, length):
	if (ret <= 0) {
		int err = SSL_get_error(con->ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			return NGHTTP2_ERR_WOUDBLOCK;
		}
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return ret;
}

static ssize_t recv_callback(nghttp2_session *session, const uint8_t *buf, ssize_t length, int flags, void *user_data) {
	Connection *conn = (Connection*)user_data;
	int ret = SSL_read(conn->ssl, buf, length);
	if (ret <= 0) {
		int err = SSL_get_error(conn->ssl, ret);
		if (err == SSL_ERR_WANT_WRITE || err == SSL_ERR_WANT_READ) {
			return NGHTTP2_ERR_WOULDBLOCK;
		}
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return ret;
}

static int on_header_callback(nghttp2_session *sesison, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data) {
	if (frame.hd->type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
		std::cout << std::string((const char*)name, namelen) << std::string((const char*)value, valuelen) << "\n";
		
	}

	return 0;
}
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
	return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
	std::cout << "Done One Stream" << "\n";
	nghttp2_nv headers[] = {
		// Method
		{
			(uint8_t *)":method",
			(uint8_t *)"GET", 
			(uint8_t)strlen(":method"), 
			(uint8_t)strlen("GET"), 
			NGHTTP2_NV_FLAG_NONE
		},
		// scheme
		{
			(uint8_t *)":scheme",
			(uint8_t *)"https",
			(uint8_t)strlen("scheme"),
			(uint8_t)strlen("https"),
			NGHTTP2_NV_FLAG_NONE
		},
		// Path
		{
			(uint8_t *)":path",
			(uint8_t *)"/",
			(uint8_t)strlen(":path"),
			(uint8_t)strlen("/"),
			NGHTTP2_NV_FLAG_NONE
		},
		// Authority
		{
			(uint8_t *)":authority",
			(uint8_t *)"www.google.com",
			(uint8_t)strlen(":authority"),
			(uint8_t)strlen("www.google.com"),
			NGHTTP2_NV_FLAG_NONE
		}
	}
	const uint32_t stream_id = nghttp2_submit_request(session, nullptr, headers, 5, nullptr, nullptr);
	if (stream_id == 0) {
		std::cout << "Done Stream Regeneration" << "\n";
	} else {
		std::cout << "Fail Stream Regeneration" << "\n";
	}
	return 0;
}

int sendRequests(const char* url, const char* port) {
	// SSL SETUP
	SSL_library_init();
	SSL_load_error_strings();
	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	const unsigned char alpn_protos[] = {2, 'h', '2'};
	SSL_CTX_set_alpn(ctx, alpn_protos, sizeof(protos));
	std::cout << "Done Setup SSL" << "\n";

	// TCP CONNECT
	addrinfo hints{}, *res;
	hints.ai_family = AF_SPEC;
	hints.ai.socktype = SOCK_STREAM;
	getaddrinfo(ip, port, &hints, &res);
	int fd = socket(res->ai.family, res->ai.socktype, res->ai.protocol);
	connect(fd, res->ai.addr, res->ai.addrlen);
	freeaddrinfo(res);
	std::cout << "Done TCP Connection" << "\n";

	//TLS HANDSHAKE
	SSL *ssl = SSL_new(ctx);
	
}
int main(int argc, char *argv[]) {
	if (argc != 3) {
		std::cout << "Usage: ./" << argv[0] << " url port" << "\n";
		return 1;
	}
	std::string url = argv[1];
	int port = std:;atoi(argv[2]);
	sendRequests(url, port);
	return 0;
}
