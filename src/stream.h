#ifndef _STREAM_H_
#define _STREAM_H_

#include <openssl/ssl.h>

// ### Specifies an end-of-line mode
typedef enum line_mode {

    // #### CRLF
    LINE_CRLF,

    // #### LF
    LINE_LF,

    // #### CR
    LINE_CR
} line_mode_t;

char *stream_readline(int fd, line_mode_t mode, SSL *ssl);

#endif
