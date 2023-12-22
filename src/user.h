#ifndef _USER_H_
#define _USER_H_

#include <stdint.h>

typedef enum {
    USER_OK,                // everything is ok
    USER_NOT_FOUND,         // the user does not exist
    USER_WRONG_PASSWORD,    // the password is wrong
    USER_INVALID_PASSWORD,  // the password is invalid (e.g. too short)
    USER_INVALID_USERNAME,  // the username is invalid (e.g. too short)
    USER_ALREADY_EXISTS,    // the user already exists
    USER_ERROR              // some other error
} user_status_t;

void init_user_table();

user_status_t add_user(const char *username, char *password);
user_status_t remove_user(const char *username);
user_status_t change_password(const char *username, const char *old_password, const char *new_password);
user_status_t login(const char *username, char *password, uint64_t *token);

#endif
