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

#ifndef SSHGUARD_WHITELIST_H
#define SSHGUARD_WHITELIST_H

#include "sshguard_addresskind.h"


/*
 * Initialize the clist containing whitelisted entries
 *
 * @return 0
 */
int whitelist_init(void);

/* 
 * compile regular expressions for each address type
 *
 * @return 0 if success, -1 if compile failed
 */
int whitelist_conf_init(void);

/*
 * free compiled regular expressions
 *
 * @return 0
 */
int whitelist_conf_fin(void);

/*
 * Free memory associated with this whitelist
 *
 * @return 0
 */
int whitelist_fin(void);

/*
 * Adds entries to whitelist from file
 *
 * @param filename The filename containing whitelist entries
 * @return 0 if success, -1 if unable to open filename 
 */
int whitelist_file(char *filename);

/* 
 * wrapper for _add_ip, _add_block and _add_host 
 *
 * @return 0 if success, -1 if failure
 */
int whitelist_add(char *str);

/*
 * add an ipv4 address to the whitelist
 *
 * @param ip character string representation of ip address
 * @return 0
 */
int whitelist_add_ipv4(char *ip);

/*
 * add an ipv6 address to the whitelist
 *
 * @param ip character string representation of ip address
 * @return 0
 */
int whitelist_add_ipv6(char *ip);

/*
 * add an ipv4 address block to the whitelist
 *
 * @param address character string representation of ip address
 * @param masklen length of bits to mask in address block 
 *
 * @return 0 if success, -1 if invalid address
 */
int whitelist_add_block4(char *address, int masklen);

/*
 * add an ipv6 address block to the whitelist
 *
 * @param address character string representation of ip address
 * @param masklen length of bits to mask in address block 
 *
 * @return 0 if success, -1 if invalid address
 */
int whitelist_add_block6(char *address, int masklen);

/*
 * add an ip address to the whitelist based on a hostname
 *
 * @param host the hostname to whitelist
 * @return 0 if success -1 if host could not be resolved
 */
int whitelist_add_host(char *host);


/*
 * search for an address in the whitelist
 *
 * @param addr the address to search for
 * @param addrkind the type of address, one of
 *                 ADDRKIND_IPv4 or ADDRKIND_IPv6
 *
 * @return 1 if the address exists in the whitelist, 0 if it doesn't
 */
int whitelist_match(char *addr, int addrkind);

#endif

