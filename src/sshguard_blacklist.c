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



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
/* for hton*() functions */
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>

#include "sshguard_addresskind.h"
#include "sshguard_log.h"
#include "sshguard_blacklist.h"

#define BL_MAXBUF      1024
#define BL_NUMENT      5

#define stringify(x)    xstr(x)
#define xstr(x)         #x


/*          UTILITY FUNCTIONS           */

/* seeks an address (key) into a list element (el). Callback for SimCList */
static int seeker_addr(const void *el, const void *key) {
    const sshg_address_t *adr = (const sshg_address_t *)key;
    const attacker_t *atk = (const attacker_t *)el;

    assert(atk != NULL && adr != NULL);
    
    if (atk->attack.address.kind != adr->kind) return 0;
    return (strcmp(atk->attack.address.value, adr->value) == 0);
}

static size_t attacker_el_meter(const void *el) {
    if (el) {}
    return sizeof(attacker_t);
}

/*          INTERFACE FUNCTIONS             */

list_t *blacklist_load(const char *filename) {
    attacker_t newattacker;
    list_t *blacklist;
    FILE *blacklist_file;
    char blacklist_line[BL_MAXBUF];
    unsigned int linecnt;

    blacklist_file = fopen(filename, "r");

    if (blacklist_file == NULL)
        return NULL;

    blacklist = (list_t *)malloc(sizeof(list_t));
    list_init(blacklist);
    list_attributes_copy(blacklist, attacker_el_meter, 1);

    /* loading content of the file in the blacklist */
    for (linecnt = 1; fgets(blacklist_line, BL_MAXBUF, blacklist_file) != NULL; ++linecnt) {
        /* discard empty lines and lines starting with a white-space or # */
        if (isspace(blacklist_line[0]) || blacklist_line[0] == '#') {
            while (blacklist_line[strlen(blacklist_line)-1] != '\n') {
                /* consume until end of line */
                if (fgets(blacklist_line, BL_MAXBUF, blacklist_file) == NULL) return blacklist;
            }
            continue;
        }

        /* line is valid, do create a list entry for it */
        if (sscanf(blacklist_line, "%lu|%d|%d|%" stringify(ADDRLEN) "s", & newattacker.whenlast,
               & newattacker.attack.service,
               & newattacker.attack.address.kind, newattacker.attack.address.value) != 4) {
            sshguard_log(LOG_NOTICE, "Blacklist entry (line #%d of '%s') appears to be malformatted. Ignoring.", linecnt, filename);
            continue;
        }
        if (newattacker.attack.address.kind != ADDRKIND_IPv4 && newattacker.attack.address.kind != ADDRKIND_IPv6) {
            /* unknown address type */
            sshguard_log(LOG_NOTICE, "Blacklist entry (line #%d of '%s') has unknown type %d. Ignoring.", linecnt, filename, newattacker.attack.address.kind);
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

    fclose(blacklist_file);

    return blacklist;
}

int blacklist_create(const char *filename) {
    FILE * blacklist_file = fopen(filename, "w");

    if (blacklist_file == NULL)
        return -1;

    fprintf(blacklist_file, "# SSHGuard blacklist file ( http://www.sshguard.net/ ).\n");
    fprintf(blacklist_file, "# Format of entries: BLACKLIST_TIMESTAMP|SERVICE|ADDRESS_TYPE|ADDRESS\n");
    fclose(blacklist_file);

    return 0;
}

int blacklist_add(const char *restrict filename, const attacker_t *restrict newel) {
    FILE * blacklist_file;
    char blacklist_line[BL_MAXBUF];
    unsigned int counter = 0;

    /* append the new attacker in the blacklist */
    blacklist_file = fopen(filename, "r+");

    if (blacklist_file == NULL)
        return -1;

    /* count existing entries */
    while (fgets(blacklist_line, BL_MAXBUF, blacklist_file) != NULL) {
        /* discard empty lines */
        // TODO: check again this condition
        if ((blacklist_line != NULL || (blacklist_line[0] == '\0')))
          continue;

        /* check if the line is a comment */
        if (blacklist_line[0] == '#')
          continue;

        ++counter;
    }

    fprintf(blacklist_file, "%lu|%d|%d|%s\n", newel->whenlast, newel->attack.service, newel->attack.address.kind, newel->attack.address.value);
    fclose(blacklist_file);

    sshguard_log(LOG_DEBUG, "Attacker '%s:%d' blacklisted. Blacklist now %d entries.", newel->attack.address.value, newel->attack.address.kind, counter);

    return 0;
}


int blacklist_lookup_address(const char *restrict filename, const sshg_address_t *restrict addr) {
    attacker_t *restrict el;
    list_t *restrict blacklist = blacklist_load(filename);

    if (blacklist == NULL)
        return -1;

    sshguard_log(LOG_DEBUG, "Looking for address '%s:%d'...", addr->value, addr->kind);
    list_attributes_seeker(blacklist, seeker_addr);

    el = list_seek(blacklist, addr);

    list_destroy(blacklist);
    free(blacklist);

    if (el != NULL)
        sshguard_log(LOG_DEBUG, "Found!");
    else
        sshguard_log(LOG_DEBUG, "Not found.");

    return (el != NULL);
}

