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

#include "sshguard.h"
#include "sshguard_logsuck.h"
#include "sshguard_options.h"
#include "sshguard_procauth.h"
#include "sshguard_whitelist.h"

sshg_opts opts;

static void usage(void) {
    fprintf(stderr, "usage: sshguard [-v] [-a thresh] [-b thresh:file]\n"
                    "\t\t[-f service:pid-file] [-i pidfile] [-l source] [-p interval]\n"
                    "\t\t[-s interval] [-w address | file]\n");
}

static void version(void) {
    fprintf(stderr, PACKAGE_STRING "\n");
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
    opt->has_polled_files = 0;
}

int get_options_cmdline(int argc, char *argv[]) {
    int optch;

    options_init(&opts);

    while ((optch = getopt(argc, argv, "b:p:s:a:w:f:l:i:e:vh")) != -1) {
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
                if (opts.abuse_threshold < DEFAULT_ATTACKS_DANGEROUSNESS) {
                    fprintf(stderr,
                            "Abuse threshold should be greater than one attack (%d danger)\n",
                            DEFAULT_ATTACKS_DANGEROUSNESS);
                    return -1;
                }

                if (opts.abuse_threshold % DEFAULT_ATTACKS_DANGEROUSNESS != 0) {
                    fprintf(stderr,
                            "Warning: abuse threshold should be a multiple of %d\n",
                            DEFAULT_ATTACKS_DANGEROUSNESS);
                }
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

            case 'f':   /* process pid authorization */
                if (procauth_addprocess(optarg) != 0) {
                    fprintf(stderr, "Could not parse service pid configuration '%s'.\n", optarg);
                    usage();
                    return -1;
                }
                break;

            case 'l':   /* add source for log sucker */
                if (! opts.has_polled_files) {
                    logsuck_init();
                }
                if (logsuck_add_logsource(optarg) != 0) {
                    fprintf(stderr, "Unable to poll from '%s'!\n", optarg);
                    return -1;
                }
                opts.has_polled_files = 1;
                break;

            case 'i':   /* specify pidfile for my PID */
                opts.my_pidfile = optarg;
                break;

            case 'v':     /* version */
                version();
                return -1;

            case 'h':   /* help */
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
