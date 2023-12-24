#include "user.h" // the c file included in server.c

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sqlite3.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "util.h"

#define SALT_LEN 16
#define HASH_LEN SHA256_DIGEST_LENGTH

#define USERS_DB "store/users.db"
#define SESSIONS_DB "store/sessions.db"

// used to clear sensitive data from memory
#define clear_string(s) memset(s, 0, strlen(s))

struct user {
    char username[USER_LEN];    // username
    uint8_t password[HASH_LEN]; // password hash
    uint8_t salt[SALT_LEN];     // salt
};

// the result of a lookup
static struct user user;
static int user_exists = 0;

void init_tables() {
    sqlite3 *db;
    int rc;
    char *err;

    rc = sqlite3_open(USERS_DB, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
    }

    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, salt TEXT)", NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        sqlite3_free(err);
    }

    sqlite3_close(db);

    rc = sqlite3_open(SESSIONS_DB, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
    }

    // token, username, timestamp
    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, timestamp INTEGER)", NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        sqlite3_free(err);
    }

    sqlite3_close(db);
}

static void hash_password(const char *password, const uint8_t *salt, uint8_t *hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen(password));
    SHA256_Update(&ctx, salt, SALT_LEN);
    SHA256_Final(hash, &ctx);
}

static int lookup_callback(void *data, int argc, char **argv, char **azColName) {
    int i;

    memset(&user, 0, sizeof(user));
    for (i = 0; i < argc; i++) {
        if (!strcmp(azColName[i], "username"))
            strncpy(user.username, argv[i], USER_LEN);
        else if (!strcmp(azColName[i], "password"))
            memcpy(user.password, argv[i], HASH_LEN);
        else if (!strcmp(azColName[i], "salt"))
            memcpy(user.salt, argv[i], SALT_LEN);
    }

    user_exists = 1;

    return 0;
}

static void lookup_user(const char *username) {
    sqlite3 *db;
    int rc;
    char *sql;
    char *err;

    memset(&user, 0, sizeof(user));
    user_exists = 0;

    rc = sqlite3_open(USERS_DB, &db);
    if (rc) return;

    sql = sqlite3_mprintf("SELECT * FROM users WHERE username='%q'", username);

    sqlite3_exec(db, sql, &lookup_callback, 0, &err);

    sqlite3_free(sql);
    sqlite3_close(db);
}

user_status_t add_user(const char *username, char *password) {
    int userlen, passlen;
    int rc;
    struct user new_user;
    sqlite3 *db;
    char *sql;
    char *err;

    if (!username || !password) {
        clear_string(password);
        return USER_ERROR;
    }

    userlen = strlen(username);
    passlen = strlen(password);

    if (userlen < USER_LEN_MIN || userlen > USER_LEN) {
        clear_string(password);
        return USER_INVALID_USERNAME;
    }

    if (passlen < PASS_LEN_MIN || passlen > PASS_LEN) {
        clear_string(password);
        return USER_INVALID_PASSWORD;
    }

    rc = RAND_bytes(new_user.salt, SALT_LEN);
    if (rc != 1) {
        clear_string(password);
        return USER_ERROR;
    }

    hash_password(password, new_user.salt, new_user.password);

    clear_string(password);

    lookup_user(username);
    if (user_exists)
        return USER_ALREADY_EXISTS;

    strncpy(new_user.username, username, USER_LEN);

    rc = sqlite3_open(USERS_DB, &db);
    if (rc)
        return USER_ERROR;
    
    sql = sqlite3_mprintf("INSERT INTO users VALUES ('%q', '%q', '%q')",
        new_user.username, new_user.password, new_user.salt);

    rc = sqlite3_exec(db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        sqlite3_free(sql);
        sqlite3_close(db);
        return USER_ERROR;
    }

    sqlite3_free(sql);
    sqlite3_close(db);

    return USER_OK;
}

user_status_t remove_user(const char *username) {
    sqlite3 *db;
    int rc;
    char *sql;

    rc = sqlite3_open(USERS_DB, &db);
    if (rc)
        return USER_ERROR;

    sql = sqlite3_mprintf("DELETE FROM users WHERE username='%q'", username);

    rc = sqlite3_exec(db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_free(sql);
        sqlite3_close(db);
        return USER_ERROR;
    }

    sqlite3_free(sql);
    sqlite3_close(db);

    return USER_OK;
}

user_status_t change_password(const char *username, char *new_password) {
    int passlen;
    int rc;
    struct user new_user;
    sqlite3 *db;
    char *sql;
    char *err;

    if (!username || !new_password) {
        clear_string(new_password);
        return USER_ERROR;
    }

    passlen = strlen(new_password);

    if (passlen < PASS_LEN_MIN || passlen > PASS_LEN) {
        clear_string(new_password);
        return USER_INVALID_PASSWORD;
    }

    lookup_user(username);
    if (!user_exists) {
        clear_string(new_password);
        return USER_NOT_FOUND;
    }

    rc = RAND_bytes(new_user.salt, SALT_LEN);
    if (rc != 1) {
        clear_string(new_password);
        return USER_ERROR;
    }

    hash_password(new_password, new_user.salt, new_user.password);

    clear_string(new_password);

    strncpy(new_user.username, username, USER_LEN);

    rc = sqlite3_open(USERS_DB, &db);
    if (rc)
        return USER_ERROR;
    
    sql = sqlite3_mprintf("UPDATE users SET password='%q', salt='%q' WHERE username='%q'",
        new_user.password, new_user.salt, new_user.username);

    rc = sqlite3_exec(db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        sqlite3_free(sql);
        sqlite3_close(db);
        return USER_ERROR;
    }

    sqlite3_free(sql);
    sqlite3_close(db);

    return USER_OK;
}

user_status_t login(const char *username, char *password, char **token) {
    int passlen;
    int rc;
    uint8_t hash[HASH_LEN];
    char *err;
    sqlite3 *db;
    char *sql;
    uint8_t tokenbuf[TOKEN_LEN];

    if (!username || !password) {
        clear_string(password);
        return USER_ERROR;
    }

    passlen = strlen(password);

    if (passlen < PASS_LEN_MIN || passlen > PASS_LEN) {
        clear_string(password);
        return USER_INVALID_PASSWORD;
    }

    // check if the user exists
    lookup_user(username);
    if (!user_exists) {
        clear_string(password);
        return USER_NOT_FOUND;
    }

    // validate the password

    hash_password(password, user.salt, hash);

    clear_string(password);

    if (memcmp(hash, user.password, HASH_LEN))
        return USER_WRONG_PASSWORD;

    rc = RAND_bytes(tokenbuf, sizeof(tokenbuf));
    if (rc != 1)
        return USER_ERROR;

    *token = tohex(tokenbuf, sizeof(tokenbuf));

    // store the session token

    rc = sqlite3_open(SESSIONS_DB, &db);
    if (rc) {
        free(*token);
        return USER_ERROR;
    }

    sql = sqlite3_mprintf("INSERT INTO sessions VALUES ('%q', '%q', %lu)",
        *token, user.username, time(NULL));

    rc = sqlite3_exec(db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
        free(*token);
        sqlite3_free(sql);
        sqlite3_close(db);
        return USER_ERROR;
    }

    sqlite3_free(sql);
    sqlite3_close(db);
    
    return USER_OK;
}

user_status_t logout(const char *token) {
    int rc;
    sqlite3 *db;
    char *sql;

    rc = sqlite3_open(SESSIONS_DB, &db);
    if (rc)
        return USER_ERROR;

    sql = sqlite3_mprintf("DELETE FROM sessions WHERE token='%q'", token);

    rc = sqlite3_exec(db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_free(sql);
        sqlite3_close(db);
        return USER_ERROR;
    }

    sqlite3_free(sql);
    sqlite3_close(db);

    fprintf(stderr, "Logged out\n");

    return USER_OK;
}

static struct userinfo *userinfo = NULL;

static int validate_callback(void *data, int argc, char **argv, char **azColName) {
    int i;

    if (!userinfo) return 0;

    for (i = 0; i < argc; i++) {
        if (!strcmp(azColName[i], "username"))
            strncpy(userinfo->username, argv[i], USER_LEN);
        else if (!strcmp(azColName[i], "timestamp"))
            userinfo->timestamp = strtoll(argv[i], NULL, 10);
    }

    user_exists = 1;
    return 0;
}

int validate_token(const char *token, struct userinfo *ui) {
    int rc;
    sqlite3 *db;
    char *sql;
    long long time_since_last_interaction;

    rc = sqlite3_open(SESSIONS_DB, &db);
    if (rc) return 0;

    sql = sqlite3_mprintf("SELECT * FROM sessions WHERE token='%q'", token);

    userinfo = ui;
    user_exists = 0;
    rc = sqlite3_exec(db, sql, &validate_callback, 0, NULL);
    userinfo = NULL;

    if (rc != SQLITE_OK) {
        sqlite3_free(sql);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_free(sql);
    sqlite3_close(db);

    if (user_exists) {

        // check if the session has timed out
        time_since_last_interaction = time(NULL) - ui->timestamp;
        if (time_since_last_interaction > SESSION_TIMEOUT) {
            logout(token);
            return 0;
        }

        return 1;
    }

    return 0;
}
