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


#ifndef SSHGUARD_FW_H
#define SSHGUARD_FW_H

#include "sshguard_services.h"
#include "sshguard_addresskind.h"

/*      return values for fw backend functions:     */
/* success */
#define FWALL_OK        0
/* error */
#define FWALL_ERR       -1
/* unsupported operation */
#define FWALL_UNSUPP    -2

/*      fw backend functions        */
/* initialization */
int fw_init();

/* finalization */
int fw_fin();

/* block an address (of kind addrkind) */
/* the buffer addr is not guaranteed to maintain its content after
 * the function returns. */
int fw_block(char *addr, int addrkind, int service);

/* release an address formerly blocked (of kind addrkind) */
/* the buffer addr is not guaranteed to maintain its content after
 * the function returns. */
int fw_release(char *addr, int addrkind, int service);


/* release all addresses formerly blocked */
int fw_flush(void);

#endif

