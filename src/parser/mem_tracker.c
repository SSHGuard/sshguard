#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mem_tracker.h"

typedef struct mem_block {
    void *ptr;
    struct mem_block *next;
} mem_block_t;

static mem_block_t *tracking_list_head = NULL;

char *track_strdup(const char *str) {
    if (!str)
        return NULL;

    char *new_str = strdup(str);
    if (!new_str) {
        perror("strdup()");
        exit(1);
    }

    mem_block_t *block = malloc(sizeof(*block));
    if (!block) {
        perror("malloc()");
        free(new_str);
        exit(1);
    }

    block->ptr = new_str;
    block->next = tracking_list_head;
    tracking_list_head = block;

    return new_str;
}

void free_all_tracked(void) {
    mem_block_t *current = tracking_list_head;
    while (current) {
        mem_block_t *next = current->next;
        free(current->ptr);
        free(current);
        current = next;
    }

    tracking_list_head = NULL;
}
