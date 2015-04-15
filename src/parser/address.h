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

#ifndef SSHGUARD_ADDRESSKIND_H
#define SSHGUARD_ADDRESSKIND_H

/* maximum length of an address string */
#ifndef INET_ADDRSTRLEN
#   define INET_ADDRSTRLEN  16
#endif
#ifndef INET6_ADDRSTRLEN
#   define INET6_ADDRSTRLEN 46
#endif
#define ADDRLEN             INET6_ADDRSTRLEN

/* address kind codes */
#define ADDRKIND_IPv4       4
#define ADDRKIND_IPv6       6

/* an IPv4 address */
#define REGEXLIB_IPV4           "((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)){3})"

/* an IPv6 address, possibly compressed */
#define REGEXLIB_IPV6           "(::|(([a-fA-F0-9]{1,4}):){7}(([a-fA-F0-9]{1,4}))|(:(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){1,6}:)|((([a-fA-F0-9]{1,4}):)(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){2}(:([a-fA-F0-9]{1,4})){1,5})|((([a-fA-F0-9]{1,4}):){3}(:([a-fA-F0-9]{1,4})){1,4})|((([a-fA-F0-9]{1,4}):){4}(:([a-fA-F0-9]{1,4})){1,3})|((([a-fA-F0-9]{1,4}):){5}(:([a-fA-F0-9]{1,4})){1,2}))"

/* an IPv4 address, mapped to IPv6 */
#define REGEXLIB_IPV4_MAPPED6   "(((0:){5}(0|[fF]{4})|:(:[fF]{4})?):{IPV4})"

/* a hostname, "localhost" or at least 2nd level */
#define REGEXLIB_HOSTNAME       "(localhost|([-a-zA-Z0-9]+\\.)+[a-zA-Z]+)"

typedef struct {
    char value[ADDRLEN];             /* address of offender */
    int kind;                   /* type of address addr */
} sshg_address_t;

#endif
