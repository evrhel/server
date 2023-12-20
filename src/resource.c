#include "resource.h"

#include <stdlib.h>
#include <regex.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

struct resource_handler {
    regex_t regex;
    resource_handler_t handler;
};

struct resource_mapping {
    char *from;
    char *to;
};

static struct resource_handler *handlers = NULL;
static int num_handlers = 0;

static struct resource_mapping *mappings = NULL;
static int num_mappings = 0;

static char *dir = 0;  // webroot
static int dirlen = 0; // length of webroot

void resource_manager_init(const char *webroot) {
    dir = realpath(webroot, NULL);
    if (!dir) {
        fprintf(stderr, "Fatal: Could not find webroot\n");
        exit(1);
    }

    dirlen = strlen(dir);
}

void resource_manager_cleanup(void) {
    int i;

    for (i = 0; i < num_handlers; i++)
        regfree(&handlers[i].regex);
    free(handlers);

    for (i = 0; i < num_mappings; i++) {
        free(mappings[i].from);
        free(mappings[i].to);
    }
    free(mappings);

    free(dir);
}

void add_resource_handler(const char *regex, resource_handler_t handler) {
    struct resource_handler *tmp;
    int reti;
    regex_t rx;

    reti = regcomp(&rx, regex, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Fatal: Could not compile regex\n");
        exit(1);
    }

    tmp = realloc(handlers, sizeof(struct resource_handler) * (num_handlers + 1));
    if (!tmp) {
        regfree(&rx);
        fprintf(stderr, "Fatal: Out of memory\n");
        exit(1);
    }

    handlers = tmp;

    handlers[num_handlers].regex = rx;
    handlers[num_handlers].handler = handler;

    num_handlers++;
}

void map_resource(const char *from, const char *to) {
    struct resource_mapping *tmp;

    tmp = realloc(mappings, sizeof(struct resource_mapping) * (num_mappings + 1));
    if (!tmp) {
        fprintf(stderr, "Fatal: Out of memory\n");
        exit(1);
    }

    mappings = tmp;

    mappings[num_mappings].from = strdup(from);
    mappings[num_mappings].to = strdup(to);

    num_mappings++;
}

static const char *get_mapping(const char *name) {
    int i;

    for (i = 0; i < num_mappings; i++) {
        if (strcmp(name, mappings[i].from) == 0)
            return mappings[i].to;
    }

    return NULL;
}

char *read_resource(const char *name, int *len, const char **content_type) {
    int i;
    int reti;
    char *r;

    if (!name) {
        *len = 0;
        *content_type = NULL;
        return NULL;
    }

    // first check explicit mappings
    for (i = 0; i < num_handlers; i++) {
        reti = regexec(&handlers[i].regex, name, 0, NULL, 0);
        if (reti == 0) {
            r = handlers[i].handler(name, len, content_type);
            if (r) return r;
        }
    }

    // then check implicit mappings
    return read_resource(get_mapping(name), len, content_type);
}

static int check_file_access(const char *path) {
    char *fullpath;
    char *tmp;
    struct stat st;
    int ret;

    fullpath = realpath(path, NULL);
    if (!fullpath) return 0;

    if (strncmp(fullpath, dir, dirlen) != 0) {
        free(fullpath);
        return 0;
    }

    // test to see if there is a file with '.' at the beginning of the name
    tmp = fullpath;
    while ((tmp = strchr(tmp, '/')) != NULL) {
        if (strlen(tmp) < 2) break;

        tmp++;
        if (tmp[0] == '.') {
            free(fullpath);
            return 0;
        }
    }

    ret = stat(fullpath, &st);

    if (ret < 0) {
        free(fullpath);
        return 0;
    }
    
    if (S_ISDIR(st.st_mode)) {
        free(fullpath);
        return 0;
    }

    ret = access(fullpath, R_OK);
    free(fullpath);

    if (ret < 0) return 0;

    return 1;
}

char *as_file_path(const char *name) {
    char *fullpath;
    char *abs;
    int len;
    int namelen;

    namelen = strlen(name);

    if (namelen == 0) return NULL;

    len = dirlen + namelen + 1;
    abs = malloc(len);
    if (!abs) return NULL;

    memcpy(abs, dir, dirlen);
    memcpy(abs + dirlen, name, namelen + 1);

    fullpath = realpath(abs, NULL);
    if (!fullpath) return NULL;

    if (strncmp(fullpath, dir, dirlen) != 0) {
        free(fullpath);
        return NULL;
    }

    return fullpath;
}

char *read_file(const char *path, int *len) {
    struct stat st;
    int fd;
    int r;

    *len = 0;

    r = stat(path, &st);
    if (r < 0) return NULL;

    if (S_ISDIR(st.st_mode)) return NULL;

    fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    *len = st.st_size;

    char *buf = malloc(*len);
    if (!buf) {
        close(fd);
        return NULL;
    }

    r = read(fd, buf, *len);

    close(fd);

    if (r < 0) {
        free(buf);
        return NULL;
    }

    return buf;
}

char *read_from_webroot(const char *name, int *len) {
    char *p;

    p = as_file_path(name);
    if (!p) return NULL;

    if (!check_file_access(p)) {
        free(p);
        return NULL;
    }

    char *r = read_file(p, len);
    free(p);

    return r;
}

const char *infer_content_type(const char *name) {
    char *ext;

    ext = strrchr(name, '.');
    if (!ext) return NULL;

    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0)
        return "text/html";
    else if (strcmp(ext, ".css") == 0)
        return "text/css";
    else if (strcmp(ext, ".js") == 0)
        return "application/javascript";
    else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
        return "image/jpeg";
    else if (strcmp(ext, ".png") == 0)
        return "image/png";
    else if (strcmp(ext, ".gif") == 0)
        return "image/gif";
    else if (strcmp(ext, ".ico") == 0)
        return "image/x-icon";
    else if (strcmp(ext, ".txt") == 0)
        return "text/plain";
    else if (strcmp(ext, ".pdf") == 0)
        return "application/pdf";
    else if (strcmp(ext, ".mp4") == 0)
        return "video/mp4";
    else if (strcmp(ext, ".mp3") == 0)
        return "audio/mpeg";
    else if (strcmp(ext, ".wav") == 0)
        return "audio/wav";
    else if (strcmp(ext, ".ogg") == 0)
        return "audio/ogg";
    else if (strcmp(ext, ".json") == 0)
        return "application/json";
    else if (strcmp(ext, ".xml") == 0)
        return "application/xml";
    else if (strcmp(ext, ".zip") == 0)
        return "application/zip";
    else if (strcmp(ext, ".tar") == 0)
        return "application/x-tar";
    else if (strcmp(ext, ".gz") == 0)
        return "application/gzip";
    else if (strcmp(ext, ".bz2") == 0)
        return "application/x-bzip2";
    else if (strcmp(ext, ".xz") == 0)
        return "application/x-xz";
    else if (strcmp(ext, ".rar") == 0)
        return "application/x-rar-compressed";
    else if (strcmp(ext, ".7z") == 0)
        return "application/x-7z-compressed";
    else if (strcmp(ext, ".exe") == 0)
        return "application/x-msdownload";
    else if (strcmp(ext, ".swf") == 0)
        return "application/x-shockwave-flash";
    else
        return NULL;
}