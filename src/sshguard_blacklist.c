/*
 * Copyright (c) 2007,2008 Mij <mij@bitchx.it>
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
 * SSHGuard. See http://sshguard.sourceforge.net
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>

#include "sshguard_addresskind.h"
#include "sshguard_log.h"
#include "sshguard_blacklist.h"

#define BL_MAXBUF      50
#define BL_NUMENT      5


/*          UTILITY FUNCTIONS           */

/* seeks an address (key) into a list element (el). Callback for SimCList */
static int seeker_addr(const void *el, const void *key) {
    const sshg_address_t *adr = (const sshg_address_t *)key;
    const attacker_t *atk = (const attacker_t *)el;

    assert(atk != NULL && adr != NULL);
    
    if (atk->attack.address.kind != adr->kind) return 0;
    return (strcmp(atk->attack.address.value, adr->value) == 0);
}

/* use custom comparator for portability: don't know sizeof(time_t) */
/*
static int time_comparator(const void *a, const void *b) {
    const attacker_t *atka = (const attacker_t *)a;
    const attacker_t *atkb = (const attacker_t *)b;

    return ((atka->whenfirst < atkb->whenfirst) - (atka->whenfirst > atkb->whenfirst));
}
*/

static void *attacker_serializer(const void *restrict el, uint32_t *restrict len) {
    /* buffer for serialization operations */
    char *serialization_buf;
    attacker_t atkr = *(const attacker_t *restrict)el;
    uint32_t val;
    

    if (el == NULL || len == NULL) return NULL;

    serialization_buf = (char *)malloc(ATTACKER_T_LEN);
    if (serialization_buf == NULL) return NULL;

    memset(serialization_buf, 0x00, ATTACKER_T_LEN);
    *len = 0;


    /* store the attacker address first */
    switch (atkr.attack.address.kind) {
        case ADDRKIND_IPv4:
            memcpy(serialization_buf, ((const attacker_t *restrict)el)->attack.address.value, INET_ADDRSTRLEN);
            break;

        case ADDRKIND_IPv6:
            memcpy(serialization_buf, ((const attacker_t *restrict)el)->attack.address.value, INET6_ADDRSTRLEN);
            break;
    }

    /* but always leap by the longest address (possible "tail" stays 0-filled) */
    *len += ADDRLEN;

    val = htonl((uint32_t)atkr.attack.address.kind);
    memcpy(serialization_buf+*len, & val, sizeof(val));
    *len += sizeof(val);

    val = htonl((uint32_t)atkr.attack.service);
    memcpy(serialization_buf+*len, & val, sizeof(val));
    *len += sizeof(val);

    val = htonl((uint32_t)atkr.whenfirst);
    memcpy(serialization_buf+*len, & val, sizeof(val));
    *len += sizeof(val);

    val = htonl((uint32_t)atkr.whenlast);
    memcpy(serialization_buf+*len, & val, sizeof(val));
    *len += sizeof(val);

    val = htonl((uint32_t)atkr.pardontime);
    memcpy(serialization_buf+*len, & val, sizeof(val));
    *len += sizeof(val);

    val = htonl((uint32_t)atkr.numhits);
    memcpy(serialization_buf+*len, & val, sizeof(val));
    *len += sizeof(val);

    assert(*len == ATTACKER_T_LEN);

    return serialization_buf;
}


static void *attacker_unserializer(const void *restrict el, uint32_t *restrict len) {
    attacker_t *atkr = malloc(sizeof(attacker_t));
    *atkr = *(const attacker_t *restrict)el;
    uint32_t val;

    memcpy(atkr->attack.address.value, el, ADDRLEN);
    *len = ADDRLEN;

    memcpy(&val, el + *len, sizeof(val));
    atkr->attack.address.kind = ntohl(val);
    *len += sizeof(val);

    memcpy(&val, el + *len, sizeof(val));
    atkr->attack.service = ntohl(val);
    *len += sizeof(val);

    memcpy(&val, el + *len, sizeof(val));
    atkr->whenfirst = ntohl(val);
    *len += sizeof(val);

    memcpy(&val, el + *len, sizeof(val));
    atkr->whenlast = ntohl(val);
    *len += sizeof(val);

    memcpy(&val, el + *len, sizeof(val));
    atkr->pardontime = ntohl(val);
    *len += sizeof(val);

    memcpy(&val, el + *len, sizeof(val));
    atkr->numhits = ntohl(val);
    *len += sizeof(val);

    assert(*len == ATTACKER_T_LEN);

    return atkr;
}



/*          INTERFACE FUNCTIONS             */
list_t *blacklist_load(const char *filename) {
    list_t * blacklist = (list_t *)malloc(sizeof(list_t));

    list_init(blacklist);
    list_attributes_unserializer(blacklist, attacker_unserializer);

    if (list_restore_file(blacklist, filename, NULL) != 0) {
        return NULL;
    }

    return blacklist;
}

int blacklist_create(const char *filename) {
    list_t blacklist;

    list_init(& blacklist);
    list_attributes_serializer(& blacklist, attacker_serializer);

    if (list_dump_file(& blacklist, filename, NULL) != 0)
        return -1;

    list_destroy(& blacklist);

    return 0;
}

int blacklist_add(const char *restrict filename, const attacker_t *restrict newel) {
    list_t *blacklist = blacklist_load(filename);

    if (blacklist == NULL)
        return -1;

    list_attributes_serializer(blacklist, attacker_serializer);

    list_prepend(blacklist, newel);

    if (list_dump_file(blacklist, filename, NULL) != 0) {
        list_destroy(blacklist);
        free(blacklist);
        return -1;
    }

    sshguard_log(LOG_DEBUG, "Attacker '%s:%d' blacklisted. Blacklist now %d entries.", newel->attack.address.value, newel->attack.address.kind, list_size(blacklist));

    list_destroy(blacklist);
    free(blacklist);

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

