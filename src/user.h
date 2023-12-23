#ifndef _USER_H_
#define _USER_H_

#include <stdint.h>

#define USER_LEN_MIN 4
#define USER_LEN 32
#define PASS_LEN_MIN 8
#define PASS_LEN 32

// length of a token in bytes
#define TOKEN_LEN 32

// The maximum number of milliseconds a session can be inactive before it is
// invalidated
#define SESSION_TIMEOUT (60ll * 60ll * 1000ll)

typedef enum {
    USER_OK,                // everything is ok
    USER_NOT_FOUND,         // the user does not exist
    USER_WRONG_PASSWORD,    // the password is wrong
    USER_INVALID_PASSWORD,  // the password is invalid (e.g. too short)
    USER_INVALID_USERNAME,  // the username is invalid (e.g. too short)
    USER_ALREADY_EXISTS,    // the user already exists
    USER_ERROR              // some other error
} user_status_t;

// Information about a user
struct userinfo {
    char username[USER_LEN + 1];    // the username
    long long timestamp;            // last interaction with the server
};

// Initialize tables
void init_tables();

// Add a new user
//
// Parameters:
// - username: the username
// - password: the password, will be cleared after the function returns
//
// Returns:
// The status of the operation
user_status_t add_user(const char *username, char *password);

// Remove a user
//
// Parameters:
// - username: the username
//
// Returns:
// The status of the operation
user_status_t remove_user(const char *username);

// Change the password of a user
//
// Parameters:
// - username: the username
// - new_password: the new password, will be cleared after the function returns
//
// Returns:
// The status of the operation
user_status_t change_password(const char *username, char *new_password);

// Try to login a user, and generate a token if successful
//
// Parameters:
// - username: the username
// - password: the password, will be cleared after the function returns
// - token: a pointer to a string where the token will be stored, if the login
//          is successful, otherwise its contents are undefined.
//
// Returns:
// The status of the operation
user_status_t login(const char *username, char *password, char **token);

// Logout a user
//
// Parameters:
// - token: the token to invalidate
//
// Returns:
// The status of the operation
user_status_t logout(const char *token);

// Validate a token
//
// Parameters:
// - token: the token to validate
// - ui: a pointer to a struct userinfo where information about the user will
//       be stored, if the token is valid, otherwise its contents are
//       undefined.
//
// Returns:
// Nonzero if the token is valid.
int validate_token(const char *token, struct userinfo *ui);

#endif
