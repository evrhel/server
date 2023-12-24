#ifndef _HTTP_H_
#define _HTTP_H_

#define HTTP10 "HTTP/1.0"
#define HTTP11 "HTTP/1.1"

#include <openssl/ssl.h>

#include "util.h"
#include "stream.h"

typedef enum {
    GET,
    POST,
    PUT,
    DELETE
} http_method_t;

typedef enum {
    CONNECTION_CLOSE,
    CONNECTION_KEEP_ALIVE
} connection_t;

typedef enum {
    SAMESITE_UNSPECIFIED,
    SAMESITE_NONE,
    SAMESITE_LAX,
    SAMESITE_STRICT
} samesite_t;

struct http_request {
    http_method_t method;
    char *target;
    char *version;
    map_t *headers;
    char *body;

    // basic header fields for convenience
    int content_length;
    char *host;
    char *user_agent;
    connection_t connection;
};

struct http_response {
    const char *version;
    int status;
    const char *reason;
    map_t *headers;
    list_t *cookies;
    char *body;

    // basic header fields for convenience
    int content_length;
    const char *server;
    const char *content_type;
    connection_t connection;
};

struct cookie {
    char *value;
    char *path;
    char *domain;
    long long expires;
    int secure;
    int http_only;
    samesite_t samesite;
};

struct http_request *http_request_read(struct stream *s);
void http_request_free(struct http_request *req);

void http_response_init(struct http_response *res);
void http_response_release(struct http_response *res);
void http_response_write(struct stream *s, struct http_response *res);
void http_response_add_cookie(struct http_response *res, const char *name, const struct cookie *cookie);

char *http_headers_get(map_t *headers, const char *key);
char *http_headers_dup(map_t *headers, const char *key);
int http_headers_geti(map_t *headers, const char *key);

// parse cookie from an http request (Cookie header)
map_t *parse_cookies(const char *str);

char *cookie_to_string(const char *name, const struct cookie *cookie);

#endif
