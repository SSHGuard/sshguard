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

#pragma once

#include <pthread.h>

#include "attack.h"

typedef struct {
    time_t expire_time;         /* The absolute time before being released */
    const attacker_t *attacker; /* Pointer to the attacker record */
} heap_node_t;

typedef struct {
    heap_node_t *array;
    size_t capacity;
    size_t size;

    pthread_mutex_t lock;
    pthread_cond_t cond;
} min_heap_t;

void heap_init(min_heap_t *heap);
void heap_insert(min_heap_t *heap, const attacker_t *attacker);
const attacker_t *heap_extract_min(min_heap_t *heap);
bool heap_contains(const min_heap_t *heap, const sshg_address_t *target);
