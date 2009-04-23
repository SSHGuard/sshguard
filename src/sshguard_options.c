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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "sshguard.h"
#include "sshguard_procauth.h"
#include "sshguard_whitelist.h"
#include "sshguard_options.h"


sshg_opts opts;


int get_options_cmdline(int argc, char *argv[]) {
    int optch;

    opts.blacklist_filename = NULL;
    opts.blacklist_threshold = DEFAULT_BLACKLIST_THRESHOLD;
    opts.pardon_threshold = DEFAULT_PARDON_THRESHOLD;
    opts.stale_threshold = DEFAULT_STALE_THRESHOLD;
    opts.abuse_threshold = DEFAULT_ABUSE_THRESHOLD;
    opts.debugging = 0;
    while ((optch = getopt(argc, argv, "b:p:s:a:w:f:dh")) != -1) {
        switch (optch) {
            case 'b':   /* threshold for blacklisting (num abuses >= this implies permanent block */
                opts.blacklist_filename = (char *)malloc(strlen(optarg)+1);
                if (sscanf(optarg, "%d:%s", &opts.blacklist_threshold, opts.blacklist_filename) == 2) {
                    /* custom threshold specified */
                    if (opts.blacklist_threshold < 1) {
                        fprintf(stderr, "Doesn't make sense to have a blacklist threshold lower than one abuse. Terminating.\n");
                        return -1;
                    }
                } else {
                    /* argument contains only the blacklist filename */
                    strcpy(opts.blacklist_filename, optarg);
                }
                break;
            case 'd':   /* enable debugging */
                opts.debugging = 1;
                break;
            case 'p':   /* pardon threshold interval */
                opts.pardon_threshold = strtol(optarg, (char **)NULL, 10);
                if (opts.pardon_threshold < 1) {
                    fprintf(stderr, "Doesn't make sense to have a pardon time lower than 1 second. Terminating.\n");
                    return -1;
                }
                break;
            case 's':   /* stale threshold interval */
                opts.stale_threshold = strtol(optarg, (char **)NULL, 10);
                if (opts.stale_threshold < 1) {
                    fprintf(stderr, "Doesn't make sense to have a stale threshold lower than 1 second. Terminating.\n");
                    return -1;
                }
                break;
            case 'a':   /* abuse threshold count */
                opts.abuse_threshold = strtol(optarg, (char **)NULL, 10);
                if (opts.abuse_threshold < 1) {
                    fprintf(stderr, "Doesn't make sense to have an abuse threshold lower than 1 attempt. Terminating.\n");
                    return -1;
                }
                break;
            case 'w':   /* whitelist entries */
                if (optarg[0] == '/' || optarg[0] == '.') {
                    /* add from file */
                    if (whitelist_file(optarg) != 0) {
                        fprintf(stderr, "Could not handle whitelisting for %s.\n", optarg);
                        return -1;
                    }
                } else {
                    /* add raw content */
                    if (whitelist_add(optarg) != 0) {
                        fprintf(stderr, "Could not handle whitelisting for %s.\n", optarg);
                        return -1;
                    }
                }
                break;
            case 'f':   /* process pid authorization */
                if (procauth_addprocess(optarg) != 0) {
                    fprintf(stderr, "Could not parse service pid configuration '%s'.\n", optarg);
                    return -1;
                }
                break;
            case 'h':   /* help */
            default:    /* or anything else: print help */
                return -1;
        }
    }

    return 0;
}
