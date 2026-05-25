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
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "sshguard_options.h"
#include "sshguard_whitelist.h"

#define CONVERSION_ERROR(str, endptr) \
    ((endptr) == (str) || *(endptr) != '\0' || errno != 0)

#define MIN_PARDON_THRESHOLD 1
#define MIN_STALE_THRESHOLD 1
#define MIN_ABUSE_THRESHOLD 1
#define MIN_MULTIPLIER_THRESHOLD 1.0f
#define MIN_SUBNET_SIZE 0
#define MAX_SUBNET_IPV6 128
#define MAX_SUBNET_IPV4 32

sshg_opts opts;

static void cmdline_error(const char *format, ...) {
    va_list arglist;

    fprintf(stderr, "Command-line usage error:\n");
    va_start(arglist, format);
    vfprintf(stderr, format, arglist);
    va_end(arglist);
    fprintf(stderr, "\nTerminating...\n");

    fflush(stderr);
}

/**
 * Initialize options to defaults.
 */
static void options_init(sshg_opts *opt) {
    opt->pardon_threshold = 2 * 60;
    opt->stale_threshold = 30 * 60;
    opt->abuse_threshold = 30;
    opt->blacklist_threshold = 0;
    opt->blacklist_filename = NULL;
    opt->subnet_ipv6 = 128;
    opt->subnet_ipv4 = 32;
    opt->mask_method = MASK_NONE;
    opt->block_time_multiplier = 2;
}

static int parse_long(const char *optarg, long *result) {
    char *endptr;

    errno = 0;
    *result = strtol(optarg, &endptr, 10);
    if (CONVERSION_ERROR(optarg, endptr))
        return -1;

    return 0;
}

static int parse_uint(const char *optarg, unsigned *result) {
    long tmp;

    if (parse_long(optarg, &tmp) != 0 || tmp > UINT_MAX || tmp < 0)
        return -1;

    *result = tmp;
    return 0;
}

static int parse_float(const char *optarg, float *result) {
    char *endptr;

    errno = 0;
    *result = strtof(optarg, &endptr);
    if (CONVERSION_ERROR(optarg, endptr))
        return -1;

    return 0;
}

int get_options_cmdline(int argc, char *argv[]) {
    int optch;

    options_init(&opts);

    while ((optch = getopt(argc, argv, "b:p:s:a:w:i:N:n:m:S")) != -1) {
        switch (optch) {
            case 'b':
                free(opts.blacklist_filename);
                opts.blacklist_filename = (char *)malloc(strlen(optarg) + 1);
                if (sscanf(optarg, "%u:%s", &opts.blacklist_threshold,
                           opts.blacklist_filename) != 2) {
                    cmdline_error("Incorrect format for -b option, expected <threshold>:<filename>");
                    return -1;
                }
                break;

            case 'p':   /* pardon threshold interval */
                if (parse_long(optarg, &opts.pardon_threshold) != 0 ||
                    opts.pardon_threshold < MIN_PARDON_THRESHOLD) {
                    cmdline_error("Not a valid number for -p option");
                    return -1;
                }
                break;

            case 's':   /* stale threshold interval */
                if (parse_long(optarg, &opts.stale_threshold) != 0 ||
                    opts.stale_threshold < MIN_STALE_THRESHOLD) {
                        cmdline_error("Not a valid number for -s option");
                        return -1;
                }
                break;

            case 'a':   /* abuse threshold count */
                if (parse_uint(optarg, &opts.abuse_threshold) != 0 ||
                    opts.abuse_threshold < MIN_ABUSE_THRESHOLD) {
                    cmdline_error("Not a valid number for -a option");
                    return -1;
                }
                break;

            case 'w':   /* whitelist entries */
                if (optarg[0] == '/' || optarg[0] == '.') {
                    /* add from file */
                    if (whitelist_file(optarg) != 0) {
                        cmdline_error("Could not handle whitelisting for '%s'", optarg);
                        return -1;
                    }
                } else {
                    /* add raw content */
                    if (whitelist_add(optarg) != 0) {
                        cmdline_error("Could not handle whitelisting for '%s'", optarg);
                        return -1;
                    }
                }
                break;

            case 'N':   /* IPv6 subnet size */
                if (parse_uint(optarg, &opts.subnet_ipv6) != 0 ||
                    opts.subnet_ipv6 < MIN_SUBNET_SIZE ||
                    opts.subnet_ipv6 > MAX_SUBNET_IPV6) {
                    cmdline_error("Not a valid number for IPv6 subnet");
                    return -1;
                }
                break;

            case 'n':   /* IPv4 subnet size */
                if (parse_uint(optarg, &opts.subnet_ipv4) != 0 ||
                    opts.subnet_ipv4 < MIN_SUBNET_SIZE ||
                    opts.subnet_ipv4 > MAX_SUBNET_IPV4) {
                    cmdline_error("Not a valid number for IPv4 subnet");
                    return -1;
                }
                break;

            case 'm':   /* block time multiplier */
                if (parse_float(optarg, &opts.block_time_multiplier) != 0 ||
                    opts.block_time_multiplier < MIN_MULTIPLIER_THRESHOLD) {
                    cmdline_error("Not a valid number for -m option");
                    return -1;
                }
                break;

            case 'S':   /* subnet masking method */
                if (strcmp(optarg, "subnet") == 0) {
                    opts.mask_method = MASK_SUBNET_SIZE;
                } else {
                    cmdline_error("Invalid subnet masking method '%s'", optarg);
                    return -1;
                }
                break;

            default:
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
