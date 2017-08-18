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

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "blocklist.h"
#include "sandbox.h"
#include "simclist.h"
#include "sshguard_blacklist.h"
#include "sshguard_log.h"
#include "sshguard_options.h"
#include "sshguard_whitelist.h"

/** Keep track of the exit signal received. */
static volatile sig_atomic_t exit_sig = 0;

/*      FUNDAMENTAL DATA STRUCTURES         */
/* These lists are all lists of attacker_t structures.
 * limbo and hell maintain "temporary" entries: in limbo, entries are deleted
 * when the address is detected to have abused a service (right after it is
 * blocked); in hell, it is deleted when the address is released.
 *
 * The list offenders maintains a permanent history of the abuses of
 * attackers, their first and last attempt, the number of abuses etc. These
 * are maintained for entire runtime. When the number of abuses exceeds a
 * limit, an address might be blacklisted (if blacklisting is enabled with
 * -b). After blacklisting, the block of an attacker is released, because it
 *  has already been blocked permanently.
 *
 *  The invariant of "offenders" is: it is sorted in decreasing order of the
 *  "whenlast" field.
 */
/* list of addresses that failed some times, but not enough to get blocked */
list_t limbo;
/* list of offenders (addresses already blocked in the past) */
list_t offenders;

/* handler for termination-related signals */
static void sigfin_handler();
/* called at exit(): flush blocked addresses and finalize subsystems */
static void finishup(void);

/* handle an attack: addr is the author, addrkind its address kind, service the attacked service code */
static void report_address(attack_t attack);
/* cleanup false-alarm attackers from limbo list (ones with too few attacks in too much time) */
static void purge_limbo_stale(void);

static void my_pidfile_create() {
    FILE *p = fopen(opts.my_pidfile, "w");
    if (p == NULL) {
        sshguard_log(LOG_ERR, "Failed to create pid file: %m");
        exit(73);
    }

    fprintf(p, "%d\n", (int)getpid());
    fclose(p);
}

static void my_pidfile_destroy() {
    if (unlink(opts.my_pidfile) != 0) {
        sshguard_log(LOG_ERR, "Failed to remove pid file: %m");
    }
}

static void init_log(int debug) {
    int flags = LOG_NDELAY | LOG_PID;
    int dest = LOG_AUTH;

    if (debug) {
        flags |= LOG_PERROR;
        dest = LOG_LOCAL6;
    } else {
        setlogmask(LOG_UPTO(LOG_NOTICE));
    }

    // Set local time zone and open log before entering sandbox.
    tzset();
    openlog("sshguard", flags, dest);
}

int main(int argc, char *argv[]) {
    int sshg_debugging = (getenv("SSHGUARD_DEBUG") != NULL);
    init_log(sshg_debugging);

    srand(time(NULL));

    /* pending, blocked, and offender address lists */
    list_init(&limbo);
    list_attributes_seeker(& limbo, attack_addr_seeker);
    blocklist_init();
    list_init(&offenders);
    list_attributes_seeker(& offenders, attack_addr_seeker);
    list_attributes_comparator(& offenders, attackt_whenlast_comparator);

    // Initialize whitelist before parsing arguments.
    whitelist_init();

    if (get_options_cmdline(argc, argv) != 0) {
        exit(64);
    }

    if (opts.my_pidfile != NULL) {
        my_pidfile_create();
        atexit(my_pidfile_destroy);
    }

    // Initialize firewall
    printf("flushonexit\n");
    fflush(stdout);

    if (opts.blacklist_filename != NULL) {
        blacklist_load_and_block();
    }

    /* termination signals */
    signal(SIGTERM, sigfin_handler);
    signal(SIGHUP, sigfin_handler);
    signal(SIGINT, sigfin_handler);
    atexit(finishup);

    sandbox_init();

    /* whitelist localhost */
    if (whitelist_add("127.0.0.1") != 0) {
        fprintf(stderr, "Could not whitelist localhost. Terminating...\n");
        exit(1);
    }

    whitelist_conf_fin();

    sshguard_log(LOG_INFO, "Now monitoring attacks.");

    char buf[1024];
    attack_t parsed_attack;
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        if (sscanf(buf, "%d %46s %d %d\n", &parsed_attack.service,
                  parsed_attack.address.value, &parsed_attack.address.kind,
                  &parsed_attack.dangerousness) == 4) {
            sshguard_log(LOG_NOTICE,
                         "Attack from \"%s\" on service %d with danger %u.",
                         parsed_attack.address.value, parsed_attack.service,
                         parsed_attack.dangerousness);
            report_address(parsed_attack);
        } else {
            sshguard_log(LOG_ERR, "Could not parse attack data.");
            exit(65);
        }
    }

    if (feof(stdin)) {
        sshguard_log(LOG_DEBUG, "Received EOF from stdin.");
    }
}

void log_block(attacker_t *tmpent, attacker_t *offenderent) {
    char time_msg[128] = "forever";
    const time_t time = tmpent->pardontime;

    unsigned int subnet_size = fw_block_subnet_size(tmpent->attack.address.kind);
    if (time > 0) {
        if (snprintf(time_msg, sizeof(time_msg), "for %lld secs", (long long)time) < 0) {
            abort();
        }
    }
    sshguard_log(LOG_WARNING, "Blocking \"%s/%u\" %s (%u attacks in %lld "
                              "secs, after %d abuses over %lld secs.)",
                 tmpent->attack.address.value, subnet_size, time_msg, tmpent->numhits,
                 (long long)(tmpent->whenlast - tmpent->whenfirst),
                 offenderent->numhits,
                 (long long)(offenderent->whenlast - offenderent->whenfirst));
}

/*
 * This function is called every time an attack pattern is matched.
 * It does the following:
 * 1) update the attacker infos (counter, timestamps etc)
 *      --OR-- create them if first sight.
 * 2) block the attacker, if attacks > threshold (abuse)
 * 3) blacklist the address, if the number of abuses is excessive
 */
static void report_address(attack_t attack) {
    attacker_t *tmpent = NULL;
    attacker_t *offenderent;

    assert(attack.address.value != NULL);
    assert(memchr(attack.address.value, '\0', sizeof(attack.address.value)) != NULL);

    /* clean list from stale entries */
    purge_limbo_stale();

    /* address already blocked? (can happen for 100 reasons) */
    if (blocklist_contains(attack)) {
        sshguard_log(LOG_INFO, "%s has already been blocked.",
                attack.address.value);
        return;
    }

    if (whitelist_match(attack.address.value, attack.address.kind)) {
        sshguard_log(LOG_INFO, "%s: not blocking (on whitelist)",
                attack.address.value);
        return;
    }
    
    /* search entry in list */
    tmpent = list_seek(& limbo, & attack.address);
    if (tmpent == NULL) { /* entry not already in list, add it */
        /* otherwise: insert the new item */
        tmpent = malloc(sizeof(attacker_t));
        attackerinit(tmpent, & attack);
        list_append(&limbo, tmpent);
    } else {
        /* otherwise, the entry was already existing, update with new data */
        tmpent->whenlast = time(NULL);
        tmpent->numhits++;
        tmpent->cumulated_danger += attack.dangerousness;
    }

    if (tmpent->cumulated_danger < opts.abuse_threshold) {
        /* do nothing now, just keep an eye on this guy */
        return;
    }

    /* otherwise, we have to block it */
    

    /* find out if this is a recidivous offender to determine the
     * duration of blocking */
    tmpent->pardontime = opts.pardon_threshold;
    offenderent = list_seek(& offenders, & attack.address);
    if (offenderent == NULL) {
        /* first time we block this guy */
        sshguard_log(LOG_DEBUG, "%s: first block (adding as offender.)",
                tmpent->attack.address.value);
        offenderent = (attacker_t *)malloc(sizeof(attacker_t));
        /* copy everything from tmpent */
        memcpy(offenderent, tmpent, sizeof(attacker_t));
        /* adjust number of hits */
        offenderent->numhits = 1;
        list_prepend(& offenders, offenderent);
        assert(! list_empty(& offenders));
    } else {
        /* this is a previous offender, update dangerousness and last-hit timestamp */
        offenderent->numhits++;
        offenderent->cumulated_danger += tmpent->cumulated_danger;
        offenderent->whenlast = tmpent->whenlast;
    }

    /* At this stage, the guy (in tmpent) is offender, and we'll block it anyway. */

    /* Let's see if we _also_ need to blacklist it. */
    if (opts.blacklist_filename != NULL &&
        offenderent->cumulated_danger >= opts.blacklist_threshold) {
        /* this host must be blacklisted -- blocked and never unblocked */
        tmpent->pardontime = 0;

        /* insert in the blacklisted db iff enabled */
        if (opts.blacklist_filename != NULL) {
            blacklist_add(offenderent);
        }
    } else {
        /* compute blocking time wrt the "offensiveness" */
        for (unsigned int i = 0; i < offenderent->numhits - 1; i++) {
            tmpent->pardontime *= 2;
        }
    }
    list_sort(& offenders, -1);
    log_block(tmpent, offenderent);

    /* append blocked attacker to the blocked list, and remove it from the pending list */
    blocklist_add(tmpent);
    assert(list_locate(& limbo, tmpent) >= 0);
    list_delete_at(& limbo, list_locate(& limbo, tmpent));
}

static void purge_limbo_stale(void) {
    sshguard_log(LOG_DEBUG, "Purging old attackers.");
    time_t now = time(NULL);
    for (unsigned int pos = 0; pos < list_size(&limbo); pos++) {
        attacker_t *tmpent = list_get_at(&limbo, pos);
        if (now - tmpent->whenfirst > opts.stale_threshold) {
            list_delete_at(&limbo, pos);
            free(tmpent);
            pos--;
        }
    }
}

static void finishup(void) {
    sshguard_log(LOG_INFO, "Exiting on %s.",
            exit_sig == SIGHUP ? "SIGHUP" : "signal");
    whitelist_fin();
    closelog();
}

static void sigfin_handler(int sig) {
    exit_sig = sig;
    exit(0);
}
