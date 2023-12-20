#include "stream.h"

#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>

#define BUFSIZE 1024

static int is_control(char c) {
    return c < 0x20 || c >= 0x7f; // ASCII control characters
}

char *stream_readline(int fd, line_mode_t mode) {
    char c = 0;
    int i;
    char *buf, *tmp;
    int len;
    char last;

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
        if (read(fd, &c, 1) < 0) {
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
