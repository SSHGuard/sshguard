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

#include <time.h>

#include "parser/address.h"

enum service {
    SERVICES_ALL            = 0,    //< anything
    SERVICES_SSH            = 100,  //< ssh
    SERVICES_UWIMAP         = 200,  //< UWimap for imap and pop daemon
    SERVICES_DOVECOT        = 210,  //< dovecot
    SERVICES_CYRUSIMAP      = 220,  //< cyrus-imap
    SERVICES_CUCIPOP        = 230,  //< cucipop
    SERVICES_EXIM           = 240,  //< exim
    SERVICES_SENDMAIL       = 250,  //< sendmail
    SERVICES_POSTFIX        = 260,  //< postfix
    SERVICES_FREEBSDFTPD    = 300,  //< ftpd shipped with FreeBSD
    SERVICES_PROFTPD        = 310,  //< ProFTPd
    SERVICES_PUREFTPD       = 320,  //< Pure-FTPd
    SERVICES_VSFTPD         = 330,  //< vsftpd
};

/* an attack (source address & target service info) */
typedef struct {
    sshg_address_t address;     //< Address
    enum service service;       //< Service
    int source;                 //< Source PID, or zero if unknown
    int dangerousness;          //< Danger level
} attack_t;

/* profile of an attacker */
typedef struct {
    attack_t attack;                /* attacker address, target service */
    time_t whenfirst;               /* first time seen (or blocked) */
    time_t whenlast;                /* last time seen (or blocked) */
    time_t pardontime;              /* minimum seconds to wait before releasing address when blocked */
    unsigned int numhits;           /* #attacks for attacker tracking; #abuses for offenders tracking */
    unsigned int cumulated_danger;  /* total danger incurred (before or after blocked) */
} attacker_t;

int attack_addr_seeker(const void *el, const void *key);
int attack_from_hostname(attack_t *attack, const char *name);
void attackerinit(attacker_t *restrict ipe, const attack_t *restrict attack);
int attackt_whenlast_comparator(const void *a, const void *b);

#endif
