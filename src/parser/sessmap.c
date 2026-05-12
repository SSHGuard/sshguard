/*
 * Copyright (c) 2026 Ilya Voronin <ivoronin@gmail.com>
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

#include "sessmap.h"

#include <stddef.h>
#include <string.h>
#include <time.h>

#define SESSMAP_SIZE 128
#define SESSMAP_TTL_SECONDS 3600
#define SESSMAP_SID_LEN 16

struct slot {
    enum service service;
    char sid[SESSMAP_SID_LEN + 1];
    sshg_address_t addr;
    time_t inserted_at;
};

static struct slot table[SESSMAP_SIZE];

static bool slot_matches(const struct slot *s, enum service service, const char *sid) {
    return s->sid[0] != '\0' && s->service == service && strcmp(s->sid, sid) == 0;
}

static struct slot *find_slot(enum service service, const char *sid) {
    for (size_t i = 0; i < SESSMAP_SIZE; i++) {
        if (slot_matches(&table[i], service, sid)) {
            return &table[i];
        }
    }
    return NULL;
}

static struct slot *find_empty_or_oldest(void) {
    struct slot *oldest = &table[0];
    for (size_t i = 0; i < SESSMAP_SIZE; i++) {
        if (table[i].sid[0] == '\0') {
            return &table[i];
        }
        if (table[i].inserted_at < oldest->inserted_at) {
            oldest = &table[i];
        }
    }
    return oldest;
}

void sessmap_put(enum service service, const char *sid, const sshg_address_t *addr) {
    struct slot *s = find_slot(service, sid);
    if (s == NULL) {
        s = find_empty_or_oldest();
    }
    s->service = service;
    memcpy(s->sid, sid, SESSMAP_SID_LEN);
    s->sid[SESSMAP_SID_LEN] = '\0';
    s->addr = *addr;
    s->inserted_at = time(NULL);
}

bool sessmap_get(enum service service, const char *sid, sshg_address_t *out) {
    struct slot *s = find_slot(service, sid);
    if (s == NULL) {
        return false;
    }
    if (time(NULL) - s->inserted_at > SESSMAP_TTL_SECONDS) {
        s->sid[0] = '\0';
        return false;
    }
    *out = s->addr;
    return true;
}

void sessmap_del(enum service service, const char *sid) {
    struct slot *s = find_slot(service, sid);
    if (s != NULL) {
        s->sid[0] = '\0';
    }
}
