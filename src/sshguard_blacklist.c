/*
 * Copyright (c) 2007,2008,2009,2011 Mij <mij@sshguard.net>
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

/*
 * SSHGuard. See http://www.sshguard.net
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser/attack.h"
#include "simclist.h"
#include "sshguard_blacklist.h"
#include "sshguard_log.h"

#define BL_MAXBUF      1024

#define stringify(x)    xstr(x)
#define xstr(x)         #x

static FILE *blacklist_file;
static list_t *blacklist;

static size_t attacker_el_meter(const void *el) {
    if (el) {}
    return sizeof(attacker_t);
}

/*          INTERFACE FUNCTIONS             */

static void blacklist_close() {
    assert(blacklist_file != NULL && blacklist != NULL);
    fclose(blacklist_file);
    blacklist_file = NULL;
    list_destroy(blacklist);
    free(blacklist);
    blacklist = NULL;
}

list_t *blacklist_load(const char *filename) {
    char blacklist_line[BL_MAXBUF];
    unsigned int linecnt;

    assert(blacklist_file == NULL && blacklist == NULL);
    blacklist_file = fopen(filename, "a+");
    if (blacklist_file == NULL) {
        return NULL;
    }

    blacklist = (list_t *)malloc(sizeof(list_t));
    list_init(blacklist);
    list_attributes_copy(blacklist, attacker_el_meter, 1);
    rewind(blacklist_file);

    /* loading content of the file in the blacklist */
    for (linecnt = 1; fgets(blacklist_line, BL_MAXBUF, blacklist_file) != NULL; ++linecnt) {
        attacker_t newattacker;

        /* discard empty lines and lines starting with a white-space or # */
        if (isspace(blacklist_line[0]) || blacklist_line[0] == '#') {
            while (blacklist_line[strlen(blacklist_line)-1] != '\n') {
                /* consume until end of line */
                if (fgets(blacklist_line, BL_MAXBUF, blacklist_file) == NULL) return blacklist;
            }
            continue;
        }

        long long blacklist_time;
        int service_no;
        if (sscanf(blacklist_line, "%lld|%d|%d|%" stringify(ADDRLEN) "s",
                    &blacklist_time, &service_no,
                    &newattacker.attack.address.kind,
                    newattacker.attack.address.value) != 4) {
            sshguard_log(LOG_NOTICE,
                    "blacklist: ignoring malformed line %d", linecnt);
            continue;
        }
        newattacker.whenlast = (time_t)blacklist_time;
        newattacker.attack.service = (enum service)service_no;

        if (newattacker.attack.address.kind != ADDRKIND_IPv4 &&
                newattacker.attack.address.kind != ADDRKIND_IPv6) {
            /* unknown address type */
            sshguard_log(LOG_NOTICE,
                    "blacklist: unknown address type on line %d", linecnt);
            continue;
        }

        /* initialization of other default information */
        newattacker.attack.dangerousness = 1;
        newattacker.whenfirst = 0;
        newattacker.pardontime = 0;
        newattacker.numhits = 1;
        newattacker.cumulated_danger = 1;

        /* add new element to the blacklist */
        list_append(blacklist, & newattacker);
    }

    atexit(blacklist_close);
    return blacklist;
}

void blacklist_add(const attacker_t *restrict newel) {
    assert(blacklist_file != NULL && blacklist != NULL);
    if (blacklist_contains(&newel->attack.address)) {
        sshguard_log(LOG_WARNING, "blacklist: %s is already blacklisted",
                newel->attack.address.value);
        return;
    }

    int retval = fprintf(blacklist_file, "%lld|%d|%d|%s\n",
            (long long)newel->whenlast, newel->attack.service,
            newel->attack.address.kind, newel->attack.address.value);
    if (retval > 0) {
        sshguard_log(LOG_NOTICE, "blacklist: added %s",
                newel->attack.address.value);
        fflush(blacklist_file);
        list_append(blacklist, newel);
    } else {
        sshguard_log(LOG_ERR, "blacklist: could not add %s: %s",
                newel->attack.address.value, strerror(errno));
    }
}

int blacklist_contains(const sshg_address_t *restrict addr) {
    if (blacklist == NULL) {
        // Blacklist hasn't been loaded yet.
        return -1;
    }

    list_attributes_seeker(blacklist, attack_addr_seeker);
    attacker_t *restrict el = list_seek(blacklist, addr);
    return (el != NULL);
}

