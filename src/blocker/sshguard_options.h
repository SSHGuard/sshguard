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

#pragma once

/* dynamic configuration options */
typedef struct {
    time_t pardon_threshold;            /* minimal time before releasing an address */
    time_t stale_threshold;             /* time after which suspicious entries remained idle are forgiven */
    unsigned int abuse_threshold;       /* number of attacks before raising an abuse */
    unsigned int blacklist_threshold;   /* number of abuses after which blacklisting the attacker */
    char *blacklist_filename;           /* NULL to disable blacklist, or path of the blacklist file */
    unsigned int subnet_ipv6;           /* size of subnets to block, CIDR notation */
    unsigned int subnet_ipv4;           /* size of subnets to block, CIDR notation */
    float increasing_factor             /* subsequent blocks increase by this factor */
} sshg_opts;

extern sshg_opts opts;

/**
 * Parses user options from the command line, environment, config file or
 * whatever.
 *
 * After execution, this function leaves the "opts" global variable compiled
 * with the user's preferences.
 *
 * @return  0 iff success; -1 if failure
 */
int get_options_cmdline(int argc, char *argv[]);
