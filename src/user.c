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

#define USER_LEN_MIN 4
#define USER_LEN 32
#define PASS_LEN_MIN 8
#define PASS_LEN 32

#define SALT_LEN 16
#define HASH_LEN SHA256_DIGEST_LENGTH

#define USERS_DB "store/users.db"

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

void init_user_table() {
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

user_status_t change_password(const char *username, const char *old_password, const char *new_password) {
    return USER_OK;
}

user_status_t login(const char *username, char *password, uint64_t *token) {
    int passlen;
    int rc;
    uint8_t hash[HASH_LEN];
    char *passhash;
    char *err;
    sqlite3 *db;
    char *sql;

    if (!username || !password) {
        clear_string(password);
        return USER_ERROR;
    }

    passlen = strlen(password);

    if (passlen < PASS_LEN_MIN || passlen > PASS_LEN) {
        clear_string(password);
        return USER_INVALID_PASSWORD;
    }

    lookup_user(username);
    if (!user_exists) {
        clear_string(password);
        return USER_NOT_FOUND;
    }

    hash_password(password, user.salt, hash);

    clear_string(password);

    if (memcmp(hash, user.password, HASH_LEN))
        return USER_WRONG_PASSWORD;

    rc = RAND_bytes((uint8_t *)token, sizeof(*token));
    if (rc != 1)
        return USER_ERROR;
    
    return USER_OK;
}
