#ifndef _HTTP_H_
#define _HTTP_H_

#define HTTP10 "HTTP/1.0"
#define HTTP11 "HTTP/1.1"

#include <openssl/ssl.h>

typedef enum {
    GET,
    POST,
    PUT,
    DELETE
} http_method_t;

struct http_header {
    char *key;
    char *value;
    struct http_header *next;
};

struct http_request {
    http_method_t method;
    char *target;
    char *version;
    struct http_header *headers;
    char *body;

    // basic header fields for convenience
    int content_length;
    char *host;
    char *user_agent;
    char *connection;
};

struct http_response {
    const char *version;
    int status;
    const char *reason;
    struct http_header *headers;
    const char *body;

    // basic header fields for convenience
    int content_length;
    const char *server;
    const char *content_type;
    const char *connection;
};

struct http_request *http_request_read(int fd, SSL *ssl);
void http_request_print(struct http_request *req);
void http_request_free(struct http_request *req);

void http_response_init(struct http_response *res);
void http_response_release(struct http_response *res);
void http_response_write(int fd, struct http_response *res, SSL *ssl);

char *http_header_get(struct http_header *headers, const char *key);
char *http_header_dup(struct http_header *headers, const char *key);
int http_header_geti(struct http_header *headers, const char *key);
struct http_header *http_header_set(struct http_header *headers, const char *key, const char *value);
void http_header_free(struct http_header *headers);

#endif
