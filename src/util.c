#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char *tohex(uint8_t *data, int len) {
    char *str;
    int i;
    int rlen;

    rlen = len * 2 + 1;
    str = malloc(rlen);
    for (i = 0; i < len; i++)
        snprintf(str + i * 2, rlen - i * 2, "%02x", data[i]);
    str[len * 2] = 0;
    return str;
}

void fromhex(const char *str, uint8_t *data, int len) {
    int i;
    char *end;

    for (i = 0; i < len; i++) {
        data[i] = strtol(str, &end, 16);
        str = end;
    }
}
