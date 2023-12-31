#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <arpa/inet.h>

#include "http.h"
#include "stream.h"
#include "resource.h"
#include "user.h"
#include "cJSON.h"

#define DEF_MAX_PENDING 10
#define DEF_WEBROOT "./webroot/"
#define DEF_CERT "./store/cert.pem"
#define DEF_KEY "./store/key.pem"

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

static const char unauthorized[] =
"<!DOCTYPE html>"
"<html>"
"<head>"
"<title>401 Unauthorized</title>"
"</head>"
"<body>"
"<h1>401 Unauthorized</h1>"
"<p>You are not authorized to access this page.</p>"
"</body>"
"</html>";

static const char forbidden[] =
"<!DOCTYPE html>"
"<html>"
"<head>"
"<title>403 Forbidden</title>"
"</head>"
"<body>"
"<h1>403 Forbidden</h1>"
"<p>You are not authorized to access this page.</p>"
"</body>"
"</html>";

static const char badrequest[] =
"<!DOCTYPE html>"
"<html>"
"<head>"
"<title>400 Bad Request</title>"
"</head>"
"<body>"
"<h1>400 Bad Request</h1>"
"<p>Your browser sent a request that this server could not understand.</p>"
"</body>"
"</html>";

static char *WEBROOT;
static int PORT = -1;
static int MAX_PENDING = DEF_MAX_PENDING;
static char *CERT = DEF_CERT;
static char *KEY = DEF_KEY;
static int HTTP = 0;
static int FORCE_HTTPS = 0;

static SSL_CTX *ssl_ctx = NULL;

static int server_fd = -1;

static void serve();
static int handle_client_connection(struct stream *s);
static int handle_request(struct http_request *req, struct http_response *res);

static void sigint_handler(int signum) {
    fprintf(stderr, "Shutting down...\n");

    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }

    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);

    resource_manager_cleanup();

    exit(0);
}

static char *default_handler(const char *name, int *len, const char **content_type) {
    *content_type = infer_content_type(name);
    if (!*content_type)
        *content_type = "text/plain";
    return read_from_webroot(name, len);
}

static void display_help() {
    fprintf(stderr, "Usage: server [options]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --port <port>              Port to listen on (default 80 for HTTP, 443 for HTTPS)\n");
    fprintf(stderr, "  -m, --max-pending <count>      Maximum pending connections (default: %d)\n", DEF_MAX_PENDING);
    fprintf(stderr, "  -w, --webroot <path>           Path to webroot (default: %s)\n", DEF_WEBROOT);
    fprintf(stderr, "  -h, --help                     Display this help message\n");
    fprintf(stderr, "  -u  --user <action> [options]  Manage users\n");
    fprintf(stderr, "  -c, --cert <path>              Path to certificate (default: %s)\n", DEF_CERT);
    fprintf(stderr, "  -k, --key <path>               Path to private key (default: %s)\n", DEF_KEY);
    fprintf(stderr, "  -t, --http                     Use HTTP instead of HTTPS\n");
    fprintf(stderr, "  -s, --https                    Force HTTPS\n");
}

static void user_help() {
    fprintf(stderr, "Usage: server -u <action> [options]\n");
    fprintf(stderr, "Actions:\n");
    fprintf(stderr, "  add <username>              Add a user\n");
    fprintf(stderr, "  remove <username>           Remove a user\n");
    fprintf(stderr, "  login <username>            Login as a user\n");
    fprintf(stderr, "  logout <token>              Logout a user\n");
    fprintf(stderr, "  validate <token>            Validate a token\n");
    fprintf(stderr, "  help                        Display this help message\n");
}

static void handle_args(int argc, char *argv[]) {
    int i;
    char *password;
    user_status_t status;
    char *action;
    char *token;
    struct userinfo ui;

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
        } else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--user")) {
            if (i + 1 >= argc) {
                user_help();
                exit(0);
            }

            action = argv[++i];

            if (!strcmp(action, "add")) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Fatal: -u add requires a username\n");
                    exit(1);
                }

                password = getpass("Password: ");
                if (!password) {
                    fprintf(stderr, "Fatal: Could not read password\n");
                    exit(1);
                }

                status = add_user(argv[++i], password);

                if (status == USER_ALREADY_EXISTS) {
                    fprintf(stderr, "Fatal: User already exists\n");
                    exit(1);
                } else if (status == USER_INVALID_PASSWORD) {
                    fprintf(stderr, "Fatal: Invalid password\n");
                    exit(1);
                } else if (status == USER_INVALID_USERNAME) {
                    fprintf(stderr, "Fatal: Invalid username\n");
                    exit(1);
                } else if (status != USER_OK) {
                    fprintf(stderr, "Fatal: Could not add user\n");
                    exit(1);
                }

                fprintf(stderr, "User added successfully\n");
                exit(0);
            } else if (!strcmp(action, "remove")) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Fatal: -u remove requires a username\n");
                    exit(1);
                }

                status = remove_user(argv[++i]);

                if (status == USER_NOT_FOUND) {
                    fprintf(stderr, "Fatal: User not found\n");
                    exit(1);
                } else if (status == USER_INVALID_USERNAME) {
                    fprintf(stderr, "Fatal: Invalid username\n");
                    exit(1);
                } else if (status != USER_OK) {
                    fprintf(stderr, "Fatal: Could not remove user\n");
                    exit(1);
                }

                fprintf(stderr, "User removed successfully\n");
                exit(0);
            } else if (!strcmp(action, "login")) {

                if (i + 1 >= argc) {
                    fprintf(stderr, "Fatal: -u login requires a username\n");
                    exit(1);
                }

                password = getpass("Password: ");
                if (!password) {
                    fprintf(stderr, "Fatal: Could not read password\n");
                    exit(1);
                }

                status = login(argv[++i], password, &token);

                if (status == USER_NOT_FOUND) {
                    fprintf(stderr, "Fatal: User not found\n");
                    exit(1);
                } else if (status == USER_WRONG_PASSWORD) {
                    fprintf(stderr, "Fatal: Wrong password\n");
                    exit(1);
                } else if (status == USER_INVALID_PASSWORD) {
                    fprintf(stderr, "Fatal: Invalid password\n");
                    exit(1);
                } else if (status == USER_INVALID_USERNAME) {
                    fprintf(stderr, "Fatal: Invalid username\n");
                    exit(1);
                } else if (status != USER_OK) {
                    fprintf(stderr, "Fatal: Could not login\n");
                    exit(1);
                }

                fprintf(stderr, "Logged in successfully\n");
                fprintf(stderr, "Token: %s\n", token);

                free(token);
                exit(0);
            } else if (!strcmp(argv[i], "logout")) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Fatal: -u logout requires a token\n");
                    exit(1);
                }

                status = logout(argv[++i]);

                if (status == USER_NOT_FOUND) {
                    fprintf(stderr, "Fatal: User not found\n");
                    exit(1);
                } else if (status != USER_OK) {
                    fprintf(stderr, "Fatal: Could not logout\n");
                    exit(1);
                }

                fprintf(stderr, "Logged out successfully\n");
                exit(0);
            } else if (!strcmp(argv[i], "validate")) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Fatal: -u validate requires a token\n");
                    exit(1);
                }

                status = validate_token(argv[++i], &ui);

                if (!status) {
                    fprintf(stderr, "Fatal: Invalid token\n");
                    exit(1);
                }

                fprintf(stderr, "Token is valid\n");
                fprintf(stderr, "Username: %s\n", ui.username);
                fprintf(stderr, "Last interaction: %lld\n", ui.timestamp);

                exit(0);
            } else if (!strcmp(argv[i], "help")) {
                user_help();
                exit(0);
            } else {
                fprintf(stderr, "Fatal: unknown action: %s\n", action);
                display_help();
                exit(1);
            }
        } else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--cert")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Fatal: -c requires an argument\n");
                exit(1);
            }

            CERT = argv[++i];
        } else if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--key")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Fatal: -k requires an argument\n");
                exit(1);
            }

            KEY = argv[++i];
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--http")) {
            HTTP = 1;
        } else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--https")) {
            HTTP = 0;
        } else {
            fprintf(stderr, "Fatal: unknown argument: %s\n", argv[i]);
            display_help();
            exit(1);
        }
    }
}

static void init_crypto() {
    SSL_library_init();
    SSL_load_error_strings();
}

static SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Fatal: Could not create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Fatal: Could not load certificate\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Fatal: Could not load private key\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    return ctx;
}

int main(int argc, char *argv[]) {
    init_crypto();
    init_tables();

    handle_args(argc, argv);

    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN); // ignore SIGPIPE (broken pipe)

    resource_manager_init(WEBROOT);

    add_resource_handler(".*$", default_handler);

    map_resource("/", "/index.html");
    
    serve();

    return 0;
}

static void serve() {
    struct sockaddr_in addr;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int server_fd, client_fd;
    pid_t pid;
    SSL *ssl;
    struct stream s;

    if (HTTP)
        ssl_ctx = 0;
    else {
        ssl_ctx = create_ssl_context();
        if (!ssl_ctx) {
            if (FORCE_HTTPS) {
                fprintf(stderr, "Fatal: Could not create SSL context\n");
                exit(1);
            }
            HTTP = 1;
            fprintf(stderr, "Warning: Could not create SSL context, using HTTP instead\n");
        }
    }

    if (PORT < 0)
        PORT = HTTP ? 80 : 443;

    fprintf(stderr, "Starting server on port %d\n", PORT);
 
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "Fatal: Could not create socket: %s\n",  strerror(errno));
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Fatal: Could not bind socket: %s\n", strerror(errno));
        exit(1);
    }
    
    fprintf(stderr, "Ready!\n");

    for (;;) {
        if (listen(server_fd, MAX_PENDING) < 0) {
            fprintf(stderr, "Fatal: Could not listen: %s\n", strerror(errno));
            exit(1);
        }

        client_addr_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0)
            continue;
        
        pid = fork();
        if (pid < 0) {
            close(client_fd);
            continue;
        } else if (pid > 0) {
            close(client_fd);
            continue;
        }

        signal(SIGINT, SIG_DFL); // reset signal handler
        
        ssl = NULL;
        if (!HTTP) {
            ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_fd);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                goto done;
            }

            stream_wrap_ssl(&s, ssl);
        } else {
            stream_wrap_fd(&s, client_fd);
        }
    
        handle_client_connection(&s);
done:
        if (!HTTP) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }

        close(client_fd);

        exit(0);
    }
}

static int handle_client_connection(struct stream *s) {
    struct http_request *req;
    struct http_response res;
    int keep_alive = 0;

    do {
        req = http_request_read(s);
        if (!req) break;

        keep_alive = req->connection == CONNECTION_KEEP_ALIVE;

        http_response_init(&res);
        if (handle_request(req, &res) < 0) {
            http_response_release(&res);
            http_request_free(req);
            break;
        }

        http_response_write(s, &res);
        http_response_release(&res);

        http_request_free(req);
    } while (keep_alive);

    return 0;
}

static int handle_get(struct http_request *req, struct http_response *res) {
    char *data;
    int len;
    const char *content_type;
    
    data = read_resource(req->target, &len, &content_type);
    if (!data) {
        res->status = 404;
        res->reason = "Not Found";

        res->body = strdup(notfound);
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

static int handle_post(struct http_request *req, struct http_response *res) {
    struct cookie cookie;
    cJSON *json;
    char *username, *password;
    map_t *cookies;
    char *token;
    struct userinfo ui;
    int rc;
    char buf[1024];

    res->status = 200;
    res->reason = "OK";

    memset(&cookie, 0, sizeof(cookie));

    if (equncase(req->target, "/app/login")) {
        json = cJSON_Parse(req->body);
        if (!json) {
            res->status = 400;
            res->reason = "Bad Request";

            res->body = strdup(badrequest);
            res->content_length = sizeof(badrequest);
            res->content_type = "text/html";
            return 0;
        }

        if (!cJSON_HasObjectItem(json, "username") || !cJSON_HasObjectItem(json, "password")) {
            res->status = 400;
            res->reason = "Bad Request";

            res->body = strdup(badrequest);
            res->content_length = sizeof(badrequest);
            res->content_type = "text/html";
            return 0;
        }

        username = cJSON_GetObjectItem(json, "username")->valuestring;
        password = cJSON_GetObjectItem(json, "password")->valuestring;

        if (!username || !password) {
            res->status = 400;
            res->reason = "Bad Request";

            res->body = strdup(badrequest);
            res->content_length = sizeof(badrequest);
            res->content_type = "text/html";
            return 0;
        }

        if (login(username, password, &cookie.value) != USER_OK) {
            res->status = 401;
            res->reason = "Unauthorized";

            res->body = strdup(unauthorized);
            res->content_length = sizeof(unauthorized);
            res->content_type = "text/html";
            return 0;
        }

        cookie.expires = time(NULL) + SESSION_TIMEOUT;
        cookie.path = "/";
        cookie.domain = NULL;
        cookie.secure = 1;
        cookie.http_only = 1;

        http_response_add_cookie(res, "auth", &cookie);

        cJSON_Delete(json);

        res->body = strdup("{}");
        res->content_length = strlen(res->body);
        res->content_type = "application/json";

        return 0;
    } else if (equncase(req->target, "/app/logout")) {
        cookies = parse_cookies(http_headers_get(req->headers, "Cookie"));

        token = map_get(cookies, "auth");
        if (!token) {
            fprintf(stderr, "No token\n");

            res->status = 401;
            res->reason = "Unauthorized";
            map_free(cookies);

            res->body = strdup(unauthorized);
            res->content_length = sizeof(unauthorized);
            res->content_type = "text/html";
            return 0;
        }

        rc = validate_token(token, &ui);
        if (!rc) {
            fprintf(stderr, "Invalid token\n");

            res->status = 401;
            res->reason = "Unauthorized";
            map_free(cookies);

            res->body = strdup(unauthorized);
            res->content_length = sizeof(unauthorized);
            res->content_type = "text/html";
            return 0;
        }

        logout(token);

        cookie.expires = time(NULL) - 1;
        cookie.path = "/";
        cookie.domain = NULL;
        cookie.secure = 1;
        cookie.http_only = 1;

        http_response_add_cookie(res, "auth", &cookie);

        map_free(cookies);

        res->body = strdup("{}");
        res->content_length = strlen(res->body);
        res->content_type = "application/json";

        return 0;
    } else if (equncase(req->target, "/app/user")) {
        cookies = parse_cookies(http_headers_get(req->headers, "Cookie"));

        token = map_get(cookies, "auth");
        if (!token) {
            res->status = 401;
            res->reason = "Unauthorized";
            map_free(cookies);

            res->body = strdup(unauthorized);
            res->content_length = sizeof(unauthorized);
            res->content_type = "text/html";
            return 0;
        }

        rc = validate_token(token, &ui);
        if (!rc) {
            res->status = 401;
            res->reason = "Unauthorized";
            map_free(cookies);

            res->body = strdup(unauthorized);
            res->content_length = sizeof(unauthorized);
            res->content_type = "text/html";
            return 0;
        }

        snprintf(buf, sizeof(buf), "{\"username\":\"%s\"}", ui.username);

        res->body = strdup(buf);
        res->content_length = strlen(res->body);
        res->content_type = "application/json";

        map_free(cookies);

        return 0;
    }

    res->status = 404;
    res->reason = "Not Found";

    res->body = strdup(notfound);
    res->content_length = sizeof(notfound);
    res->content_type = "text/html";
    return 0;
}

static int handle_request(struct http_request *req, struct http_response *res) {
    res->connection = req->connection;

    switch (req->method) {
    case GET:
        return handle_get(req, res);
        break;
    case POST:
        return handle_post(req, res);
        break;
    default:
        res->status = 405;
        res->reason = "Method Not Allowed";
        break;
    }

    return 0;
}
