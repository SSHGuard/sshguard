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
#include "sshguard_logsuck.h"
#include "sshguard_options.h"

sshg_opts opts;

/* dumps usage message to standard error */
static void usage(void);
/* dumps version message to standard error */
static void version(void);

int get_options_cmdline(int argc, char *argv[]) {
    int optch;

    opts.blacklist_filename = NULL;
    opts.blacklist_threshold = DEFAULT_BLACKLIST_THRESHOLD;
    opts.pardon_threshold = DEFAULT_PARDON_THRESHOLD;
    opts.stale_threshold = DEFAULT_STALE_THRESHOLD;
    opts.abuse_threshold = DEFAULT_ABUSE_THRESHOLD;
    opts.has_polled_files = 0;
    while ((optch = getopt(argc, argv, "b:p:s:a:w:f:l:vdh")) != -1) {
        switch (optch) {
            case 'b':   /* threshold for blacklisting (num abuses >= this implies permanent block */
                opts.blacklist_filename = (char *)malloc(strlen(optarg)+1);
                if (sscanf(optarg, "%u:%s", & opts.blacklist_threshold, opts.blacklist_filename) == 2) {
                    /* custom threshold specified */
                    if (opts.blacklist_threshold < DEFAULT_ABUSE_THRESHOLD) {
                        fprintf(stderr, "Doesn't make sense to have a blacklist threshold lower than one abuse (%u). Terminating.\n", DEFAULT_ABUSE_THRESHOLD);
						usage();
						return -1;
                    }
                } else {
                    /* argument contains only the blacklist filename */
                    strcpy(opts.blacklist_filename, optarg);
                }
                break;

            case 'd':   /* (historical) debugging */
                fprintf(stderr, "Debugging mode now uses environment variable. Run:\n\tenv SSHGUARD_DEBUG=\"\" %s ...\n", argv[0]);
                return -1;

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
                if (opts.abuse_threshold < 1) {
                    fprintf(stderr, "Doesn't make sense to have an abuse threshold lower than 1 attempt. Terminating.\n");
					usage();
					return -1;
                } else if (opts.abuse_threshold < DEFAULT_ABUSE_THRESHOLD) {
                    fprintf(stderr, "Warning! Sshguard now uses *attack dangerousness*, not occurrences, to gauge threats.\n");
                    fprintf(stderr, "Default dangerousness per attack is %u, default threshold is %d.\n", DEFAULT_ATTACKS_DANGEROUSNESS, DEFAULT_ABUSE_THRESHOLD);
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

            case 'l':
                if (! opts.has_polled_files) {
                    logsuck_init();
                }
                if (logsuck_add_logsource(optarg) != 0) {
                    fprintf(stderr, "Unable to poll from '%s'!\n", optarg);
                    return -1;
                }
                opts.has_polled_files = 1;
                break;

			case 'v': 	/* version */
				version();
				return -1;

            case 'h':   /* help */
            default:    /* or anything else: print help */
				usage();
				return -1;
        }
    }

    return 0;
}

static void usage(void) {
    fprintf(stderr, "Usage:\nsshguard [-d] [-b <thr:file>] [-a num] [-p sec] [-w <whlst>]{0,n} [-s sec] [-l c] [-f srv:pidfile]{0,n}\n");
    /* fprintf(stderr, "\t-d\tDebugging mode: don't fork to background, and dump activity to stderr.\n"); */
    fprintf(stderr, "\t-b\tBlacklist: thr = number of abuses before blacklisting, file = blacklist filename.\n");
    fprintf(stderr, "\t-a\tNumber of hits after which blocking an address (%d)\n", DEFAULT_ABUSE_THRESHOLD);
    fprintf(stderr, "\t-p\tSeconds after which unblocking a blocked address (%d)\n", DEFAULT_PARDON_THRESHOLD);
    fprintf(stderr, "\t-w\tWhitelisting of addr/host/block, or take from file if starts with \"/\" or \".\" (repeatable)\n");
    fprintf(stderr, "\t-s\tSeconds after which forgetting about a cracker candidate (%d)\n", DEFAULT_STALE_THRESHOLD);
    fprintf(stderr, "\t-f\t\"authenticate\" service's logs through its process pid, as in pidfile\n");
    fprintf(stderr, "\t-v\tDump version message to stderr, supply this when reporting bugs\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "\tThe SSHGUARD_DEBUG environment variable enables debugging mode (verbosity + interactivity).\n");
}

static void version(void) {
	fprintf(stderr, "sshguard %d.%d.%d\n\n", MAJOR_VERSION, MINOR_VERSION, BUILD_VERSION);
	fprintf(stderr, "Copyright (c) 2007,2008 Mij <mij@sshguard.net>\n");
	fprintf(stderr, "This is free software; see the source for conditions on copying.\n");
}
