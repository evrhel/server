#ifndef _USER_H_
#define _USER_H_

#include <stdint.h>

typedef enum {
    USER_OK,
    USER_NOT_FOUND,
    USER_WRONG_PASSWORD,
    USER_ALREADY_EXISTS,
    USER_ERROR
} user_status_t;

void init_crypto();

user_status_t add_user(const char *username, const char *password);
user_status_t remove_user(const char *username);
user_status_t change_password(const char *username, const char *old_password, const char *new_password);
user_status_t login(const char *username, const char *password, uint64_t *token);

#endif
