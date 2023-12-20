#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

#include "http.h"
#include "stream.h"
#include "resource.h"

#define DEF_PORT 80
#define DEF_MAX_PENDING 10
#define DEF_WEBROOT "./webroot/"

static const char notfound[] =
"<!DOCTYPE html>"
"<html>"
"<head>"
"<title>404 Not Found</title>"
"</head>"
"<body>"
"<h1>404 Not Found</h1>"
"<p>The page that you have requested could not be found.</p>"
"</body>"
"</html>";

static int server_fd = -1;

static void serve();
static int handle_request(struct http_request *req, struct http_response *res);

static void sigint_handler(int signum) {
    fprintf(stderr, "Shutting down...\n");

    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }

    resource_manager_cleanup();

    exit(0);
}

static char *default_handler(const char *name, int *len, const char **content_type) {
    *content_type = infer_content_type(name);
    if (!*content_type)
        *content_type = "text/plain";
    return read_from_webroot(name, len);
}

static char *WEBROOT;
static int PORT = DEF_PORT;
static int MAX_PENDING = DEF_MAX_PENDING;

static void display_help() {
    fprintf(stderr, "Usage: server [options]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --port <port>          Port to listen on (default: %d)\n", DEF_PORT);
    fprintf(stderr, "  -m, --max-pending <count>  Maximum pending connections (default: %d)\n", DEF_MAX_PENDING);
    fprintf(stderr, "  -w, --webroot <path>       Path to webroot (default: %s)\n", DEF_WEBROOT);
}

static void handle_args(int argc, char *argv[]) {
    int i;

    WEBROOT = DEF_WEBROOT;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Fatal: -p requires an argument\n");
                exit(1);
            }

            PORT = atoi(argv[++i]);
            if (PORT <= 0 || PORT > 65535) {
                fprintf(stderr, "Fatal: invalid port number\n");
                exit(1);
            }
        } else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--max-pending")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Fatal: -m requires an argument\n");
                exit(1);
            }

            MAX_PENDING = atoi(argv[++i]);
            if (MAX_PENDING <= 0) {
                fprintf(stderr, "Fatal: invalid max pending connections\n");
                exit(1);
            }
        } else if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--webroot")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Fatal: -w requires an argument\n");
                exit(1);
            }

            WEBROOT = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            display_help();
            exit(0);
        } else {
            fprintf(stderr, "Fatal: unknown argument: %s\n", argv[i]);
            display_help();
            exit(1);
        }
    }
}

int main(int argc, char *argv[]) {
    handle_args(argc, argv);

    signal(SIGINT, sigint_handler);

    resource_manager_init(WEBROOT);

    add_resource_handler(".*$", default_handler);

    map_resource("/", "/index.html");
    
    serve();

    signal(SIGINT, SIG_DFL);

    return 0;
}

static void serve() {
    struct http_request *req;
    struct http_response res;
    struct sockaddr_in addr;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int server_fd, client_fd;

    fprintf(stderr, "Starting server on port %d\n", PORT);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "Fatal: Could not create socket\n");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Fatal: Could not bind socket\n");
        exit(1);
    }

    fprintf(stderr, "Ready!\n");
    while (1) {
        if (listen(server_fd, MAX_PENDING) < 0) {
            fprintf(stderr, "Fatal: Could not listen\n");
            exit(1);
        }

        client_addr_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            fprintf(stderr, "Warning: failed to accept connection\n");
            continue;
        }
        
        req = http_request_read(client_fd);
        if (!req) {
            fprintf(stderr, "Warning: failed to read request\n");
            close(client_fd);
            continue;
        }

        http_response_init(&res);
        if (handle_request(req, &res) < 0) {
            fprintf(stderr, "Warning: failed to handle request\n");
            http_response_release(&res);
            http_request_free(req);
            close(client_fd);
            continue;
        }

        http_response_write(client_fd, &res);
        http_response_release(&res);

        http_request_free(req);
        close(client_fd);
    }
}

static int handle_get(struct http_request *req, struct http_response *res) {
    char *data;
    int len;
    const char *content_type;

    data = read_resource(req->target, &len, &content_type);
    if (!data) {
        res->status = 404;
        res->reason = "Not Found";

        res->body = notfound;
        res->content_length = sizeof(notfound);
        res->content_type = "text/html";

        return 0;
    }

    res->status = 200;
    res->reason = "OK";

    res->body = data;
    res->content_length = len;
    res->content_type = content_type;

    return 0;
}

static int handle_request(struct http_request *req, struct http_response *res) {
    switch (req->method) {
    case GET:
        return handle_get(req, res);
        break;
    default:
        res->status = 405;
        res->reason = "Method Not Allowed";
        break;
    }

    return 0;
}

#include "user.c"
#include "http.c"
#include "resource.c"
#include "stream.c"
