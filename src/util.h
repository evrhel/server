#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>

typedef void (*free_fn)(void *);

// doubly linked list node
typedef struct list_node {
    void *data;                     // data
    struct list_node *prev, *next;  // prev and next node
} list_node_t;

// doubly linked list
typedef struct list {
    list_node_t *head;  // head of list
} list_t;

// entry in associative list
typedef struct entry {
    char *key;      // key
    void *value;    // pointer to data
} entry_t;

// Callback on update of entry, called when entry is added, removed
// or updated. It is guaranteed that old != cur. Calling any
// map_* function in this callback will result in undefined behavior.
//
// Parameters:
// - key: key of entry.
// - old: old value, NULL if new entry.
// - cur: new value, NULL if removed entry.
typedef void (*update_fn)(const char *key, void *old, void *cur);

// associative list
typedef struct map {
    list_t *list;                           // list of entries
    int (*equ)(const char *, const char *); // equality function
    update_fn on_update;                    // callback on update
} map_t;

// convert data to hex string
//
// Parameters:
// - data: data to convert
// - len: length of data
//
// Return:
// A hex string
char *tohex(uint8_t *data, int len);

// convert hex string to data
//
// Parameters:
// - str: hex string
// - data: data to store
// - len: maximum length of data
void fromhex(const char *str, uint8_t *data, int len);

// Case insensitive string comparison
//
// Parameters:
// - s1: string 1
// - s2: string 2
//
// Return:
// Non-zero if equal, zero otherwise.
int equncase(const char *s1, const char *s2);

// Remove leading and trailing whitespace from string
//
// Parameters:
// - str: string to trim
//
// Return:
// Trimmed string, must be freed.
char *trim(char *str);

list_t *list_new();
void list_free(list_t *list, free_fn free);
void list_push_front(list_t *list, void *data);
void *list_pop_front(list_t *list);
void *list_remove(list_t *list, list_node_t *node);

map_t *map_new(int ignore_case, update_fn on_update);
void map_free(map_t *map);
void map_set(map_t *map, const char *key, void *value);
entry_t *map_get_entry(map_t *map, const char *key);
void *map_get(map_t *map, const char *key);
void map_remove(map_t *map, const char *key);

#endif
