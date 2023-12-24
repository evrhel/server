#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

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

int equncase(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2 && *s1 != *s2 + 32 && *s1 != *s2 - 32)
            return 0;
        s1++;
        s2++;
    }
    return *s1 == *s2;
}

char *trim(char *str) {
    char *end;

    while (*str && isspace(*str)) str++;
    if (!*str) return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    *(end + 1) = 0;

    return str;
}

static list_node_t *list_node_new(void *data) {
    list_node_t *node;

    node = calloc(1, sizeof(list_node_t));
    node->data = data;
    return node;
}

list_t *list_new() {
    return calloc(1, sizeof(list_t));
}

void list_free(list_t *list, free_fn free) {
    list_node_t *node, *next;

    if (!list) return;

    node = list->head;
    while (node) {
        next = node->next;
        if (free)
            free(node->data);

        free(node);
        node = next;
    }

    free(list);
}

void list_push_front(list_t *list, void *data) {
    list_node_t *node;

    node = list_node_new(data);
    if (list->head) {
        node->next = list->head;
        list->head->prev = node;
    }
    list->head = node;
}

void *list_pop_front(list_t *list) {
    list_node_t *node;
    void *data;

    if (!list->head) return NULL;

    node = list->head;
    list->head = node->next;
    if (list->head) list->head->prev = NULL;

    data = node->data;
    free(node);
    return data;
}

void *list_remove(list_t *list, list_node_t *node) {
    void *data;

    if (!node) return NULL;

    data = node->data;
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    if (list->head == node) list->head = node->next;
    free(node);

    return data;
}

static int streq(const char *s1, const char *s2) {
    return strcmp(s1, s2) == 0;
}

map_t *map_new(int ignore_case, update_fn on_update) {
    map_t *map;

    map = calloc(1, sizeof(map_t));
    map->list = list_new();
    map->equ = ignore_case ? equncase : streq;
    map->on_update = on_update;
    return map;
}

void map_free(map_t *map) {
    list_node_t *node;
    entry_t *entry;

    if (!map) return;

    node = map->list->head;
    while (node) {
        entry = node->data;

        if (map->on_update) {
            map->on_update(entry->key, entry->value, NULL);
        }

        free(entry->key);
        free(entry);

        node = node->next;
    }

    list_free(map->list, 0);
    free(map);
}

void map_set(map_t *map, const char *key, void *value) {
    list_node_t *node;
    entry_t *entry;

    node = map->list->head;
    while (node) {
        entry = node->data;
        if (map->equ(entry->key, key)) {
            if (entry->value != value && map->on_update)
                map->on_update(entry->key, entry->value, value);

            entry->value = value;
            return;
        }
        node = node->next;
    }

    entry = malloc(sizeof(entry_t));
    entry->key = strdup(key);
    entry->value = value;

    if (map->on_update)
        map->on_update(entry->key, NULL, entry->value);

    list_push_front(map->list, entry);
}

entry_t *map_get_entry(map_t *map, const char *key) {
    list_node_t *node;
    entry_t *entry;

    node = map->list->head;
    while (node) {
        entry = node->data;
        if (map->equ(entry->key, key))
            return entry;
        node = node->next;
    }
    return NULL;
}

void *map_get(map_t *map, const char *key) {
    entry_t *entry;

    entry = map_get_entry(map, key);
    if (!entry) return NULL;

    return entry->value;
}

void map_remove(map_t *map, const char *key) {
    list_node_t *node;
    entry_t *entry;

    node = map->list->head;
    while (node) {
        entry = node->data;
        if (map->equ(entry->key, key)) {
            if (map->on_update)
                map->on_update(entry->key, entry->value, NULL);

            list_remove(map->list, node);
        }
        node = node->next;
    }
}
