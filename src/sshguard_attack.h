/*
 * Copyright (c) 2007,2008,2010 Mij <mij@sshguard.net>
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

#ifndef SSHGUARD_ATTACK_H
#define SSHGUARD_ATTACK_H

#include "sshguard_addresskind.h"

#include <time.h>

/* an attack (source address & target service info) */
typedef struct {
    sshg_address_t address;         /* address (value + type) */
    int service;                    /* type of service offended */
    unsigned int dangerousness;     /* how dangerous the attack is, the bigger the worse */
} attack_t;

/* portable definition of the length in bytes of the attack_t structure */
#define ATTACK_T_LEN            (SSHG_ADDRESS_T_LEN + 4)

/* profile of an attacker */
typedef struct {
    attack_t attack;                /* attacker address, target service */
    time_t whenfirst;               /* first time seen (or blocked) */
    time_t whenlast;                /* last time seen (or blocked) */
    time_t pardontime;              /* minimum seconds to wait before releasing address when blocked */
    unsigned int numhits;           /* #attacks for attacker tracking; #abuses for offenders tracking */
    unsigned int cumulated_danger;  /* total danger incurred (before or after blocked) */
} attacker_t;

/* portable definition of the length in bytes of the attacker_t structure */
#define ATTACKER_T_LEN          (ATTACK_T_LEN + 3*4 + 4)

#endif

