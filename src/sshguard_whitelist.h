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


int whitelist_init(void);

int whitelist_conf_init(void);
int whitelist_conf_fin(void);

int whitelist_fin(void);

int whitelist_file(char *filename);

/* wrapper for _add_ip, _add_block and _add_host */
int whitelist_add(char *str);

int whitelist_add_ipv4(char *ip);
int whitelist_add_ipv6(char *ip);
int whitelist_add_block4(char *address, int masklen);
int whitelist_add_block6(char *address, int masklen);
int whitelist_add_host(char *host);

int whitelist_match(char *addr, int addrkind);

#endif

