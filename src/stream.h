#ifndef _STREAM_H_
#define _STREAM_H_

#include <openssl/ssl.h>
#include <stdint.h>

// ### Specifies an end-of-line mode
typedef enum line_mode {

    // #### CRLF
    LINE_CRLF,

    // #### LF
    LINE_LF,

    // #### CR
    LINE_CR
} line_mode_t;

struct stream;

typedef int(*stream_read_fn)(struct stream *s, void *buf, int len);
typedef int(*stream_write_fn)(struct stream *s, const void *buf, int len);

// Wrapper for file descriptor or SSL connection. Use the
// stream_wrap_* functions to create streams.
struct stream {
    intptr_t stream;
    stream_read_fn read;        // read function
    stream_write_fn write;      // write function
};

// Wrap file descriptor into stream.
//
// Parameters:
// - s: The stream
// - fd: The file descriptor
void stream_wrap_fd(struct stream *s, int fd);

// Wrap SSL connection into stream.
//
// Parameters:
// - s: The stream
// - ssl: The SSL connection
void stream_wrap_ssl(struct stream *s, SSL *ssl);

char *stream_readline(struct stream *s, line_mode_t mode);

int stream_printf(struct stream *s, const char *fmt, ...);

#endif
