/*
 * Copyright (c) 2007,2008,2009 Mij <mij@sshguard.net>
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

#ifndef SSHGUARD_BLACKLIST_H
#define SSHGUARD_BLACKLIST_H

#include <simclist.h>

#include "sshguard_attack.h"

/**
 * Load the blacklist contained at a given filename.
 *
 * Load the blacklist from a file with full path specified at "filename" into
 * a list_t object, and return it.
 *
 * @param filename  full path of the file containing the black list
 * @return          NULL in case of error, or a list containing blacklisted entries
 */
list_t *blacklist_load(const char *filename);

/**
 * Create an empty blacklist.
 *
 * Create an empty blacklist file at "filename". If such file already
 * exists, it is overwritten.
 *
 * @param filename  full path of the file to create
 * @return          0 if successfull, non-0 otherwise
 */
int blacklist_create(const char *filename);

/**
 * Add an entry to the blacklist.
 *
 * @param filename  full path of the file containing the black list
 * @param newel     ip entry to add
 *
 * @return          0 if successful, non-0 otherwise
 */
int blacklist_add(const char *restrict filename, const attacker_t *restrict newel);


/**
 * Lookup if an address is present in the blacklist.
 *
 * @param filename  full path of the file containing the black list
 * @param addr      address to look up (value + type)
 *
 * @return          <0 if error; 1 if (addr,addrkind) present in blacklist, 0 otherwise
 */
int blacklist_lookup_address(const char *restrict filename, const sshg_address_t *restrict addr);

#endif

