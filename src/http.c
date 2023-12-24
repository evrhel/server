#include "http.h"

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include "stream.h"
#include "util.h"

#define COOKIE_MAX_LEN 4096
#define TMP_BUF_LEN 256

static void on_update_headers(const char *key, void *old, void *cur) {
    free(old);
}

static void on_update_cookies(const char *key, void *old, void *cur) {
    free(old);
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

struct http_request *http_request_read(struct stream *s) {
    char *line;
    struct http_request *req;
    size_t len;
    char *key, *value;
    char *tmp;

    line = stream_readline(s, LINE_CRLF);
    if (!line)
        return NULL;

    req = calloc(1, sizeof(struct http_request));

    if (parse_startline(line, req) < 0) {
        free(line);
        http_request_free(req);
        return NULL;
    }

    req->headers = map_new(1, &on_update_headers);

    for (;;) {
        free(line);

        line = stream_readline(s, LINE_CRLF);
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
        if (!value || strlen(value) == 0) {
            free(line);
            http_request_free(req);
            return NULL;
        }

        map_set(req->headers, key, strdup(value));
    }

    free(line);

    req->content_length = http_headers_geti(req->headers, "Content-Length");
    if (req->content_length) {
        req->body = malloc(req->content_length);
        if (!req->body) {
            http_request_free(req);
            return NULL;
        }

        if (s->read(s, req->body, req->content_length) < 0) {
            http_request_free(req);
            return NULL;
        }
    }

    req->host = http_headers_dup(req->headers, "Host");
    req->user_agent = http_headers_dup(req->headers, "User-Agent");
    req->connection = http_headers_dup(req->headers, "Connection");

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

void http_request_free(struct http_request *req) {
    if (!req) return;

    free(req->target);
    free(req->version);
    map_free(req->headers);
    free(req->body);
    free(req->host);
    free(req->user_agent);
    free(req->connection);
    free(req);
}

void http_response_init(struct http_response *res) {
    memset(res, 0, sizeof(struct http_response));
    res->version = HTTP11;
    res->headers = map_new(1, &on_update_headers);
    res->cookies = list_new();
}

void http_response_release(struct http_response *res) {
    list_node_t *node;

    if (!res) return;
    map_free(res->headers);

    list_free(res->cookies, &free);
}

void http_response_write(struct stream *s, struct http_response *res) {
    char buf[256];
    list_node_t *node;
    entry_t *entry;
    char *val;

    // status line
    stream_printf(s, "%s %d %s\r\n", res->version, res->status, res->reason);

    if (res->content_length > 0)
        stream_printf(s, "Content-Length: %d\r\n", res->content_length);

    if (res->server)
        stream_printf(s, "Server: %s\r\n", res->server);

    if (res->content_type)
        stream_printf(s, "Content-Type: %s\r\n", res->content_type);
    
    if (res->connection)
        stream_printf(s, "Connection: %s\r\n", res->connection);

    // cookies
    fprintf(stderr, "writing cookies\r\n");
    node = res->cookies->head;
    while (node) {
        stream_printf(s, "Set-Cookie: %s\r\n", (char *)node->data);
        node = node->next;
    }

    // headers
    node = res->headers->list->head;
    while (node) {
        entry = node->data;
        stream_printf(s, "%s: %s\r\n", entry->key, (char *)entry->value);
        node = node->next;
    }

    s->write(s, "\r\n", 2);

    if (res->body)
        s->write(s, res->body, res->content_length);
}

void http_response_add_cookie(struct http_response *res, const char *name, const struct cookie *cookie) {
    char *value;

    value = cookie_to_string(name, cookie);
    if (!value) return;

    list_push_front(res->cookies, value);
}

char *http_headers_get(map_t *headers, const char *key) {
    return map_get(headers, key);
}

char *http_headers_dup(map_t *headers, const char *key) {
    char *val;

    val = map_get(headers, key);
    if (!val) return NULL;

    return strdup(val);
}

int http_headers_geti(map_t *headers, const char *key) {
    char *val;

    val = map_get(headers, key);
    if (!val) return 0;

    return atoi(val);
}

map_t *parse_cookies(const char *str) {
    map_t *cookies;
    char *tmp, *key, *value;

    cookies = map_new(1, &on_update_cookies);

    if (!str) return cookies;

    tmp = strdup(str);
    while (tmp) {
        key = strsep(&tmp, ";");
        if (!key) break;

        value = strchr(key, '=');
        if (!value) break;

        *value = 0;
        value++;

        key = trim(key);
        if (!key || strlen(key) == 0) continue;

        value = trim(value);
        if (!value || strlen(value) == 0) continue;

        map_set(cookies, key, strdup(value));
    }

    free(tmp);

    return cookies;
}

char *cookie_to_string(const char *name, const struct cookie *cookie) {
    char *result;
    char tmp[TMP_BUF_LEN];
    char date_str[64];
    time_t t;

    if (!name || !cookie || !cookie->value) return NULL;

    result = malloc(COOKIE_MAX_LEN);
    if (!result) return NULL;

    strncpy(result, name, COOKIE_MAX_LEN);
    strncat(result, "=", COOKIE_MAX_LEN);

    strncat(result, cookie->value, COOKIE_MAX_LEN);

    if (cookie->path) {
        strncat(result, "; Path=", COOKIE_MAX_LEN);
        strncat(result, cookie->path, COOKIE_MAX_LEN);
    }

    if (cookie->domain) {
        strncat(result, "; Domain=", COOKIE_MAX_LEN);
        strncat(result, cookie->domain, COOKIE_MAX_LEN);
    }

    if (cookie->expires > 0) {
        t = cookie->expires;
        strftime(date_str, 64, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
        snprintf(tmp, TMP_BUF_LEN, "; Expires=%s", date_str);
        strncat(result, tmp, COOKIE_MAX_LEN);
    }

    if (cookie->secure)
        strncat(result, "; Secure", COOKIE_MAX_LEN);

    if (cookie->http_only)
        strncat(result, "; HttpOnly", COOKIE_MAX_LEN);
    
    switch (cookie->samesite) {
    case SAMESITE_STRICT:
        strncat(result, "; SameSite=Strict", COOKIE_MAX_LEN);
        break;
    case SAMESITE_LAX:
        strncat(result, "; SameSite=Lax", COOKIE_MAX_LEN);
        break;
    case SAMESITE_NONE:
        strncat(result, "; SameSite=None", COOKIE_MAX_LEN);
        break;
    default:
        break;
    }

    return result;
}
