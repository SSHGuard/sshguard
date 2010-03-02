/*
 * Copyright (c) 2007,2008 Mij <mij@sshguard.net>
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


/**
 * Initialize the whitelisting subsystem.
 *
 * Any other whitelist_*() function must be executed
 * after this. This function cannot be executed twice
 * unless whitelist_fin() occurred in between.
 *
 * @return  0 if success, <0 if failure
 *
 * @see whitelist_fin()
 */
int whitelist_init(void);

/**
 * Start a session for configuring the whitelist.
 *
 * The whitelist subsystem must have been initialized first.
 * Calls to whitelist_add*() must occur only between this
 * function's call and whitelist_conf_fin()'s call.
 *
 * @return 0 if success, <0 if compile failed
 *
 * @see whitelist_conf_fin()
 */
int whitelist_conf_init(void);

/**
 * End a session for configuring the whitelist.
 *
 * @return 0
 */
int whitelist_conf_fin(void);

/**
 * Terminate the whitelisting subsystem.
 *
 * No calls to any whitelist_*() function can occur after
 * this, unless whitelist_init() is called first.
 *
 * @return  0 if success, <0 if failure
 */
int whitelist_fin(void);

/**
 * Adds entries to whitelist from file.
 *
 * The file is human readable and line-based. Entries look like:
 *
 *  # comment line (a '#' as very first character)
 *  #   a single ip address
 *  1.2.3.4
 *  #   address blocks in CIDR notation
 *  127.0.0.0/8
 *  10.11.128.0/17
 *  192.168.0.0/24
 *  #   hostnames
 *  rome-fw.enterprise.com
 *  hosts.friends.com
 *
 * @param filename  The filename containing whitelist entries
 * @return          0 if success, -1 if unable to open filename 
 */
int whitelist_file(const char *restrict filename);

/**
 * Wrapper for _add_ip, _add_block and _add_host.
 *
 * @return 0 if success, <0 if failure
 *
 * @see whitelist_add_ipv4()
 * @see whitelist_add_ipv6()
 * @see whitelist_add_block4()
 * @see whitelist_add_block6()
 * @see whitelist_add_host()
 */
int whitelist_add(const char *restrict str);

/**
 * Add an IPv4 address to the whitelist.
 *
 * @param ip    ip address, in dotted decimal notation
 * @return      0 if success, <0 if failure
 */
int whitelist_add_ipv4(const char *restrict ip);

/**
 * Add an IPv6 address to the whitelist.
 *
 * @param ip    ip address, in numerical string notation
 * @return      0 if success, <0 if failure
 */
int whitelist_add_ipv6(const char *restrict ip);

/**
 * Add an IPv4 address block to the whitelist
 *
 * @param address character string representation of ip address
 * @param masklen length of bits to mask in address block 
 *
 * @return 0 if success, -1 if invalid address
 */
int whitelist_add_block4(const char *restrict address, int masklen);

/**
 * Add an IPv6 address block to the whitelist
 *
 * @param address character string representation of ip address
 * @param masklen length of bits to mask in address block 
 *
 * @return 0 if success, -1 if invalid address
 */
int whitelist_add_block6(const char *restrict address, int masklen);

/**
 * add an ip address to the whitelist based on a hostname
 *
 * @param host the hostname to whitelist
 * @return 0 if success -1 if host could not be resolved
 */
int whitelist_add_host(const char *restrict host);


/**
 * search for an address in the whitelist
 *
 * @param addr the address to search for
 * @param addrkind the type of address, one of
 *                 ADDRKIND_IPv4 or ADDRKIND_IPv6
 *
 * @return 1 if the address exists in the whitelist, 0 if it doesn't
 */
int whitelist_match(const char *restrict addr, int addrkind);

#endif

