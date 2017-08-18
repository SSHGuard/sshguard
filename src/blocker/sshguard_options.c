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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "sshguard_options.h"
#include "sshguard_whitelist.h"

sshg_opts opts;

static void usage(void) {
    fprintf(stderr, "sshg-blocker: invalid command-line\n");
}

/**
 * Initialize options to defaults.
 */
static void options_init(sshg_opts *opt) {
    opt->pardon_threshold = 2 * 60;
    opt->stale_threshold = 30 * 60;
    opt->abuse_threshold = 30;
    opt->blacklist_threshold = 0;
    opt->my_pidfile = NULL;
    opt->blacklist_filename = NULL;
    opt->subnet_ipv6 = 128;
    opt->subnet_ipv4 = 32;
}

int get_options_cmdline(int argc, char *argv[]) {
    int optch;

    options_init(&opts);

    while ((optch = getopt(argc, argv, "b:p:s:a:w:i:N:n:")) != -1) {
        switch (optch) {
            case 'b':
                opts.blacklist_filename = (char *)malloc(strlen(optarg) + 1);
                if (sscanf(optarg, "%u:%s", &opts.blacklist_threshold,
                           opts.blacklist_filename) != 2) {
                    usage();
                    return -1;
                }
                break;

            case 'p':   /* pardon threshold interval */
                opts.pardon_threshold = strtol(optarg, (char **)NULL, 10);
                if (opts.pardon_threshold < 1) {
                    fprintf(stderr, "Doesn't make sense to have a pardon time lower than 1 second. Terminating.\n");
                    usage();
                    return -1;
                }
                break;

            case 's':   /* stale threshold interval */
                opts.stale_threshold = strtol(optarg, (char **)NULL, 10);
                if (opts.stale_threshold < 1) {
                    fprintf(stderr, "Doesn't make sense to have a stale threshold lower than 1 second. Terminating.\n");
                    usage();
                    return -1;
                }
                break;

            case 'a':   /* abuse threshold count */
                opts.abuse_threshold = strtol(optarg, (char **)NULL, 10);
                break;

            case 'w':   /* whitelist entries */
                if (optarg[0] == '/' || optarg[0] == '.') {
                    /* add from file */
                    if (whitelist_file(optarg) != 0) {
                        fprintf(stderr, "Could not handle whitelisting for %s.\n", optarg);
                        usage();
                        return -1;
                    }
                } else {
                    /* add raw content */
                    if (whitelist_add(optarg) != 0) {
                        fprintf(stderr, "Could not handle whitelisting for %s.\n", optarg);
                        usage();
                        return -1;
                    }
                }
                break;

            case 'N':   /* IPv6 subnet size */
                opts.subnet_ipv6 = strtol(optarg, (char **)NULL, 10);
                break;

            case 'n':   /* IPv4 subnet size */
                opts.subnet_ipv4 = strtol(optarg, (char **)NULL, 10);
                break;

            case 'i':   /* specify pidfile for my PID */
                opts.my_pidfile = optarg;
                break;

            default:    /* or anything else: print help */
                usage();
                return -1;
        }
    }

    if (opts.blacklist_filename &&
            opts.blacklist_threshold < opts.abuse_threshold) {
        fprintf(stderr, "error: blacklist (%u) is less than abuse threshold (%u)\n",
                opts.blacklist_threshold, opts.abuse_threshold);
        return -1;
    }

    return 0;
}
