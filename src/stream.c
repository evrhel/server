#include "stream.h"

#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <stdarg.h>

#define BUFSIZE 1024

static int is_control(char c) {
    return c < 0x20 || c >= 0x7f; // ASCII control characters
}

static int ssl_read_thunk(struct stream *s, void *buf, int len) {
    return SSL_read((SSL *)s->stream, buf, len);
}

static int ssl_write_thunk(struct stream *s,const void *buf, int len) {
    return SSL_write((SSL *)s->stream, buf, len);
}

static int read_thunk(struct stream *s, void *buf, int len) {
    return read((int)s->stream, buf, len);
}

static int write_thunk(struct stream *s,const void *buf, int len) {
    return write((int)s->stream, buf, len);
}

void stream_wrap_fd(struct stream *s, int fd) {
    s->stream = (intptr_t)fd;
    s->read = &read_thunk;
    s->write = &write_thunk;
}

void stream_wrap_ssl(struct stream *s, SSL *ssl) {
    s->stream = (intptr_t)ssl;
    s->read = &ssl_read_thunk;
    s->write = &ssl_write_thunk;
}

char *stream_readline(struct stream *s, line_mode_t mode) {
    char c = 0;
    int i;
    char *buf, *tmp;
    int len;
    char last;
    int rc;

    if (mode != LINE_CRLF && mode != LINE_LF && mode != LINE_CR) return NULL;

    len = BUFSIZE;
    buf = malloc(len);
    if (!buf) return NULL;

    i = 0;
    for (;;) {
        // grow buffer if necessary
        if (i == len) {
            len += BUFSIZE;
            tmp = realloc(buf, len);
            if (!tmp) {
                free(buf);
                return NULL;
            }
        }
        
        // read a character
        last = c;
        rc = s->read(s, &c, 1);
        if (rc < 0) {
            free(buf);
            return NULL;
        }

        // check for end of line
        switch (mode) {
        case LINE_CRLF:
            if (last == '\r' && c == '\n') {
                buf[i] = 0;
                return buf;
            }
            break;
        case LINE_LF:
            if (c == '\n') {
                buf[i] = 0;
                return buf;
            }
            break;
        case LINE_CR:
            if (c == '\r') {
                buf[i] = 0;
                return buf;
            }
            break;
        }

        if (is_control(c))
            continue; // skip control characters

        buf[i++] = c;
    }

    buf[len - 1] = 0; // always null-terminate
    return buf;
}

int stream_printf(struct stream *s, const char *fmt, ...) {
    char buf[BUFSIZE];
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);

    return s->write(s, buf, len);
}
