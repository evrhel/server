#include "http.h"

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include "stream.h"

static int equncase(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2 && *s1 != *s2 + 32 && *s1 != *s2 - 32)
            return 0;
        s1++;
        s2++;
    }
    return *s1 == *s2;
}

static char *trim(char *str) {
    char *end;

    while (*str && isspace(*str)) str++;
    if (!*str) return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    *(end + 1) = 0;

    return str;
}

static int parse_startline(char *line, struct http_request *req) {
    char *methodstr;
    
    methodstr = strsep(&line, " ");
    if (!methodstr) return -1;

    req->target = strsep(&line, " ");
    if (!req->target) return -1;

    req->version = strsep(&line, " ");
    if (!req->version) return -1;

    if (equncase(methodstr, "GET"))
        req->method = GET;
    else if (equncase(methodstr, "POST"))
        req->method = POST;
    else if (equncase(methodstr, "PUT"))
        req->method = PUT;
    else if (equncase(methodstr, "DELETE"))
        req->method = DELETE;
    else
        return -1;

    if (req->target)
        req->target = strdup(req->target);
    else
        req->target = strdup("/");

    if (req->version)
        req->version = strdup(req->version);
    else
        req->version = strdup(HTTP11);

    return 0;
}

struct http_request *http_request_read(int fd) {
    char *line;
    struct http_request *req;
    size_t len;
    char *key, *value;
    char *tmp;

    line = stream_readline(fd, LINE_CRLF);
    if (!line) return NULL;

    req = calloc(1, sizeof(struct http_request));

    if (parse_startline(line, req) < 0) {
        free(line);
        http_request_free(req);
        return NULL;
    }

    for (;;) {
        free(line);

        line = stream_readline(fd, LINE_CRLF);
        if (!line) {
            http_request_free(req);
            return NULL;
        }

        len = strlen(line);
        if (len == 0) break;

        tmp = line;

        key = strsep(&tmp, ":");
        if (!key) {
            free(line);
            http_request_free(req);
            return NULL;
        }

        // check to make sure there is a value
        if (!tmp) {
            free(line);
            http_request_free(req);
            return NULL;
        }

        value = trim(tmp);

        // empty values are not allowed
        if (strlen(value) == 0) {
            free(line);
            http_request_free(req);
            return NULL;
        }

        req->headers = http_header_set(req->headers, key, value);
    }

    free(line);

    req->content_length = http_header_geti(req->headers, "Content-Length");
    if (req->content_length) {
        req->body = malloc(req->content_length);
        if (!req->body) {
            http_request_free(req);
            return NULL;
        }

        if (read(fd, req->body, req->content_length) < 0) {
            http_request_free(req);
            return NULL;
        }
    }

    req->host = http_header_dup(req->headers, "Host");
    req->user_agent = http_header_dup(req->headers, "User-Agent");
    req->connection = http_header_dup(req->headers, "Connection");

    return req;
}

static const char *methodstr(http_method_t method) {
    switch (method) {
    case GET:
        return "GET";
    case POST:
        return "POST";
    case PUT:
        return "PUT";
    case DELETE:
        return "DELETE";
    default:
        return NULL;
    }
}

void http_request_print(struct http_request *req) {
    struct http_header *header;

    fprintf(stderr, "method: %s\n", methodstr(req->method));
    fprintf(stderr, "target: %s\n", req->target);
    fprintf(stderr, "version: %s\n", req->version);

    header = req->headers;
    while (header) {
        fprintf(stderr, "%s: %s\n", header->key, header->value);
        header = header->next;
    }

    fprintf(stderr, "body: %s\n", req->body);
}

void http_request_free(struct http_request *req) {
    if (!req) return;

    free(req->target);
    free(req->version);
    http_header_free(req->headers);
    free(req->body);
    free(req->host);
    free(req->user_agent);
    free(req->connection);
    free(req);
}

void http_response_init(struct http_response *res) {
    memset(res, 0, sizeof(struct http_response));
    res->version = HTTP11;
}

void http_response_release(struct http_response *res) {
    if (!res) return;
    http_header_free(res->headers);
}

void http_response_write(int fd, struct http_response *res) {
    char buf[256];
    struct http_header *header;

    snprintf(buf, sizeof(buf), "%s %d %s\r\n", res->version, res->status, res->reason);
    write(fd, buf, strlen(buf));

    if (res->content_length > 0)
        snprintf(buf, sizeof(buf), "Content-Length: %d\r\n", res->content_length);

    if (res->server)
        snprintf(buf, sizeof(buf), "Server: %s\r\n", res->server);

    if (res->content_type)
        snprintf(buf, sizeof(buf), "Content-Type: %s\r\n", res->content_type);
    
    if (res->connection)
        snprintf(buf, sizeof(buf), "Connection: %s\r\n", res->connection);

    header = res->headers;
    while (header) {
        snprintf(buf, sizeof(buf), "%s: %s\r\n", header->key, header->value);
        write(fd, buf, strlen(buf));
        header = header->next;
    }

    write(fd, "\r\n", 2);

    if (res->body)
        write(fd, res->body, res->content_length);
}

char *http_header_get(struct http_header *headers, const char *key) {
    while (headers) {
        if (equncase(headers->key, key))
            return headers->value;
        headers = headers->next;
    }
    return NULL;
}

char *http_header_dup(struct http_header *headers, const char *key) {
    char *val;

    val = http_header_get(headers, key);
    if (!val) return NULL;

    return strdup(val);
}

int http_header_geti(struct http_header *headers, const char *key) {
    char *val;

    val = http_header_get(headers, key);
    if (!val) return 0;

    return atoi(val);
}

struct http_header *http_header_set(struct http_header *headers, const char *key, const char *value) {
    struct http_header *header;
    char *newval;

    if (!key || !value) return headers;

    header = headers;
    while (header) {
        if (equncase(header->key, key)) {
            if (header->value) {
                free(header->value);
                header->value = NULL;
            }

            newval = strdup(value);
            if (newval) 
                header->value = newval;

            return headers;
        }

        header = header->next;
    }

    header = malloc(sizeof(struct http_header));
    if (!header) return headers;

    header->key = strdup(key);
    if (!header->key) {
        free(header);
        return headers;
    }

    header->value = strdup(value);
    if (!header->value) {
        free(header->key);
        free(header);
        return headers;
    }

    header->next = headers;
    return header;
}

void http_header_free(struct http_header *headers) {
    struct http_header *next;
    while (headers) {
        next = headers->next;
        free(headers->key);
        free(headers->value);
        free(headers);
        headers = next;
    }
}
