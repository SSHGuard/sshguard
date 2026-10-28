/*
 * Copyright (c) 2026 Mehran Hashemi <mehranstock1383@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "heap.h"
#include "sshguard_log.h"

void heap_init(min_heap_t *heap) {
    int ret = 0;

    heap->size = 0;
    heap->capacity = 1;

    ret += pthread_mutex_init(&heap->lock, NULL);
    ret += pthread_cond_init(&heap->cond, NULL);

    heap->array = malloc(sizeof(heap_node_t) * heap->capacity);
    if (ret != 0 || !heap->array) {
        sshguard_log(LOG_ERR, "heap initialization failed");
        exit(1);
    }
}

static void swap_nodes(heap_node_t *a, heap_node_t *b) {
    heap_node_t temp = *a;
    *a = *b;
    *b = temp;
}

void heap_insert(min_heap_t *heap, const attacker_t *attacker) {
    if (heap->size == heap->capacity) {
        heap->capacity *= 2;
        heap->array = realloc(heap->array, heap->capacity * sizeof(heap_node_t));
        if (!heap->array) {
            perror("realloc()");
            return;
        }
    }

    size_t i = heap->size++;
    heap->array[i].expire_time = attacker->pardontime + time(NULL);
    heap->array[i].attacker = attacker;

    while (i != 0 && heap->array[(i - 1) / 2].expire_time > heap->array[i].expire_time) {
        swap_nodes(&heap->array[i], &heap->array[(i - 1) / 2]);
        i = (i - 1) / 2;
    }

    /* If the new node became the root, it is the first arrived attack
     * or it expires earlier than our previous earliest node, so we must
     * interrupt the sleeping thread.
     */
    if (i == 0)
        pthread_cond_signal(&heap->cond);
}

const attacker_t *heap_extract_min(min_heap_t *heap) {
    if (heap->size == 0)
        return NULL;

    if (heap->size == 1) {
        heap->size--;
        return heap->array[0].attacker;
    }

    const attacker_t *root = heap->array[0].attacker;
    heap->array[0] = heap->array[heap->size - 1];
    heap->size--;

    size_t i = 0, left, right, smallest;
    while (true) {
        left = 2 * i + 1;
        right = 2 * i + 2;
        smallest = i;

        if (left < heap->size && heap->array[left].expire_time < heap->array[smallest].expire_time)
            smallest = left;
        if (right < heap->size && heap->array[right].expire_time < heap->array[smallest].expire_time)
            smallest = right;

        if (smallest != i) {
            swap_nodes(&heap->array[i], &heap->array[smallest]);
            i = smallest;
        } else {
            break;
        }
    }

    return root;
}

bool heap_contains(const min_heap_t *heap, const sshg_address_t *target) {
    const attacker_t *attacker;
    for (size_t i = 0; i < heap->size; i++) {
        attacker = heap->array[i].attacker;
        if (strcmp(attacker->attack.address.value, target->value) == 0)
            return true;
    }
    return false;
}
