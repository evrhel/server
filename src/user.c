#include "user.h" // the c file included in server.c

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#ifndef NO_OPENSSL
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#endif

#define USER_LEN_MIN 4
#define USER_LEN 32
#define PASS_LEN_MIN 8
#define PASS_LEN 32
#define SALT_LEN 16

struct user {
    char username[USER_LEN + 1];
    char password[PASS_LEN + 1];
};

static struct user *users = NULL;
static struct user *users_end = NULL;
static int user_fd = -1;
static struct flock user_lock;

void init_crypto() {
#ifndef NO_OPENSSL
    OpenSSL_add_all_algorithms();
    RAND_poll();
#endif
}

static int acquire_user_store() {
    if (user_fd < 0) {
        user_fd = open("store/users", O_RDWR | O_CREAT, 0600);
        if (user_fd < 0) return -1;

        user_lock.l_type = F_WRLCK;
        user_lock.l_whence = SEEK_SET;
        user_lock.l_start = 0;
        user_lock.l_len = 0;

        if (fcntl(user_fd, F_SETLK, &user_lock) < 0) {
            close(user_fd);
            user_fd = -1;
            return -1;
        }

        return 0;
    }

    return 0;
}

static int release_user_store() {
    if (user_fd >= 0) {
        user_lock.l_type = F_UNLCK;
        fcntl(user_fd, F_SETLK, &user_lock);

        close(user_fd);
    }

    return 0;
}

static int open_user_store() {
    struct stat st;

    if (user_fd < 0) {
        user_fd = open("store/users", O_RDWR | O_CREAT, 0600);
        if (user_fd < 0) return -1;

        fstat(user_fd, &st);

        users = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, user_fd, 0);
        if (users == MAP_FAILED) {
            close(user_fd);
            user_fd = -1;
            return -1;
        }

        users_end = (struct user *) ((uint8_t *) users + st.st_size);
    }

    return 0;
}

static int close_user_store() {
    if (user_fd >= 0) {
        munmap(users, users_end - users);
        close(user_fd);
        user_fd = -1;

        users = NULL;
        users_end = NULL;
    }

    return 0;
}

static struct user *lookup_user(const char *username) {
    /*    if (acquire_user_store() < 0)
        return NULL;

    for (int i = 0; i < st.st_size; i += sizeof(struct user)) {
        struct user *u = (struct user *) (buf + i);
        if (strcmp(u->username, username) == 0) {
            munmap(buf, st.st_size);
            close(fd);
            return i;
        }
    }*/
    return NULL;
}

user_status_t add_user(const char *username, const char *password) {
    int userlen, passlen;
    if (!username || !password)
        return USER_ERROR;

    userlen = strlen(username);
    passlen = strlen(password);

    if (userlen < USER_LEN_MIN || userlen > USER_LEN)
        return USER_ERROR;

    if (passlen < PASS_LEN_MIN || passlen > PASS_LEN)
        return USER_ERROR;

    

    return USER_OK;
}

user_status_t remove_user(const char *username) {
    return USER_OK;
}

user_status_t change_password(const char *username, const char *old_password, const char *new_password) {
    return USER_OK;
}

user_status_t login(const char *username, const char *password, uint64_t *token) {
    return USER_OK;
}


#ifdef _BUILD_USER_UTIL_ // for command-line utility

int main(int argc, char *argv[]) {
    return 0;
}

#endif