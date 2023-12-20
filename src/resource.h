#ifndef _RESOURCE_H_
#define _RESOURCE_H_

typedef char *(*resource_handler_t)(const char *name, int *len, const char **content_type);

void add_resource_handler(const char *regex, resource_handler_t handler);
void map_resource(const char *from, const char *to);

void resource_manager_init(const char *webroot);
void resource_manager_cleanup(void);

char *read_resource(const char *name, int *len, const char **content_type);

char *as_file_path(const char *name);
char *read_file(const char *path, int *len);

char *read_from_webroot(const char *name, int *len);

const char *infer_content_type(const char *name);

#endif
