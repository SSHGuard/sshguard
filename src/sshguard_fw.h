/*
 * Copyright (c) 2007,2008,2009,2010 Mij <mij@sshguard.net>
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
/**
 * Initialize the firewall.
 *
 * This function is called once, at the beginning. All
 * the other firewall's functions are called thereafter.
 *
 * @return FWALL_OK or FWALL_ERR
 *
 * @see fw_release()
 */
int fw_init();


/**
 * Terminate the firewall.
 *
 * This function is called once, at the end. No other
 * firewall functions are called thereafter.
 *
 * @return FWALL_OK or FWALL_ERR
 */
int fw_fin();


/**
 * Block an address.
 *
 * Block an address of a given kind and for a given service.
 *
 * @param addr          the address (string representation)
 * @param addrkind      the kind of the given address
 * @param service       the target service when blocking addr
 *
 * @return FWALL_OK or FWALL_ERR
 */
int fw_block(const char *restrict addr, int addrkind, int service);


/**
 * Block a list of addresses.
 *
 * Block a given list of addresses, all of the same kind and
 * destined to the same service.
 *
 * @param addresses     an array of strings, one per address to be blocked
 * @param addrkind      the type of all addresses in addresses[]
 * @param service       an array of integers, service[i] is the target service when blocking addresses[i]
 *
 * @return FWALL_OK or FWALL_ERR
 */
int fw_block_list(const char *restrict addresses[], int addrkind, const int service_codes[]);


/**
 * Release an address.
 *
 * @param addr          the address (string representation)
 * @param addrkind      the kind of the given address
 * @param service       the target service when blocking addr
 *
 * @return FWALL_OK or FWALL_ERR
 *
 * @see fw_block()
 * @see fw_flush()
 */
int fw_release(const char *restrict addr, int addrkind, int service);


/**
 * Release all blocked addresses.
 *
 * @return FWALL_OK or FWALL_ERR
 */
int fw_flush(void);

#endif

