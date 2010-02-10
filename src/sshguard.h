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
 * SSHGuard. See http://www.sshguard.net
 */

#ifndef SSHGUARD_H
#define SSHGUARD_H

#include "sshguard_addresskind.h"

/* these may be changed with runtime options! */

/* default: minimum seconds after which unblocking a blocked IP. Max is (min*3/2) */
#define DEFAULT_PARDON_THRESHOLD    (7 * 60)
/* default cumulated danger after which blocking an IP (inclusive) */
#define DEFAULT_ABUSE_THRESHOLD     40
/* default seconds after which forgiving a cracker candidate */
#define DEFAULT_STALE_THRESHOLD     (20 * 60)
/* default total cumulated danger from which an offender (attacker blocked in the past) gets blacklisted and blocked permanently */
#define DEFAULT_BLACKLIST_THRESHOLD (3 * DEFAULT_ABUSE_THRESHOLD)
#if DEFAULT_BLACKLIST_THRESHOLD < DEFAULT_ABUSE_THRESHOLD
#   error   "Doesn't make sense to blacklist before blocking. Set DEFAULT_BLACKLIST_THRESHOLD >= DEFAULT_ABUSE_THRESHOLD."
#endif

/* default "weight" of an attack */
#define DEFAULT_ATTACKS_DANGEROUSNESS           10


/* maximum number of recent offenders to retain in memory at once */
#define MAX_OFFENDER_ITEMS      15

/* maximum number of files polled */
#define MAX_FILES_POLLED        35
/* maximum file polling interval when logs are idle (millisecs) */
#define MAX_LOGPOLL_INTERVAL    2200

#endif
