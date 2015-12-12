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

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "parser/parser.h"
#include "simclist.h"
#include "sshguard.h"
#include "sshguard_blacklist.h"
#include "sshguard_fw.h"
#include "sshguard_log.h"
#include "sshguard_logsuck.h"
#include "sshguard_options.h"
#include "sshguard_procauth.h"
#include "sshguard_whitelist.h"

#define MAX_LOGLINE_LEN     1000

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
/* list of addresses currently blocked (offenders) */
list_t hell;
/* list of offenders (addresses already blocked in the past) */
list_t offenders;

/* mutex against races between insertions and pruning of lists */
pthread_mutex_t list_mutex;

/* get log lines in here. Hide the actual source and the method. Fill buf up
 * to buflen chars, return 0 for success, -1 for failure */
static int read_log_line(char *restrict buf, sourceid_t *restrict source_id);
/* handler for termination-related signals */
static void sigfin_handler();
/* called at exit(): flush blocked addresses and finalize subsystems */
static void finishup(void);

/* load blacklisted addresses and block them (if blacklist enabled) */
static void process_blacklisted_addresses();
/* handle an attack: addr is the author, addrkind its address kind, service the attacked service code */
static void report_address(attack_t attack);
/* cleanup false-alarm attackers from limbo list (ones with too few attacks in too much time) */
static void purge_limbo_stale(void);
/* release blocked attackers after their penalty expired */
static void *pardonBlocked();

/* create or destroy my own pidfile */
static void my_pidfile_create(void);
static void my_pidfile_destroy(void);

int main(int argc, char *argv[]) {
    pthread_t tid;
    sourceid_t source_id;
    char buf[MAX_LOGLINE_LEN];

    int sshg_debugging = (getenv("SSHGUARD_DEBUG") != NULL);
    sshguard_log_init(sshg_debugging);
    yy_flex_debug = sshg_debugging;
    yydebug = sshg_debugging;

    srand(time(NULL));

    /* pending, blocked, and offender address lists */
    list_init(&limbo);
    list_attributes_seeker(& limbo, attack_addr_seeker);
    list_init(&hell);
    list_attributes_seeker(& hell, attack_addr_seeker);
    list_init(&offenders);
    list_attributes_seeker(& offenders, attack_addr_seeker);
    list_attributes_comparator(& offenders, attackt_whenlast_comparator);

    // Initialize procauth and whitelist before parsing arguments.
    procauth_init();
    whitelist_init();
    if (whitelist_conf_init() != 0) {
        fprintf(stderr, "Could not initialize the whitelist engine.\n");
        exit(1);
    }

    if (get_options_cmdline(argc, argv) != 0) {
        exit(64);
    }

    /* create pidfile, if requested */
    if (opts.my_pidfile != NULL) {
        my_pidfile_create();
        atexit(my_pidfile_destroy);
    }

    if (fw_init() != FWALL_OK) {
        sshguard_log(LOG_ERR, "Failed to initialize firewall");
        exit(69);
    }

    // Load blacklist and block listed addresses.
    process_blacklisted_addresses();

    /* termination signals */
    signal(SIGTERM, sigfin_handler);
    signal(SIGHUP, sigfin_handler);
    signal(SIGINT, sigfin_handler);
    atexit(finishup);

    // TODO: Privilege separation goes here!

    /* whitelist localhost */
    if (whitelist_add("127.0.0.1") != 0) {
        fprintf(stderr, "Could not whitelist localhost. Terminating...\n");
        exit(1);
    }

    whitelist_conf_fin();

    /* start thread for purging stale blocked addresses */
    pthread_mutex_init(&list_mutex, NULL);
    if (pthread_create(&tid, NULL, pardonBlocked, NULL) != 0) {
        perror("pthread_create()");
        exit(2);
    }

    sshguard_log(LOG_INFO, "Monitoring attacks from %s",
            opts.has_polled_files ? "log files" : "stdin");

    while (read_log_line(buf, &source_id) == 0) {
        attack_t parsed_attack;

        if (parse_line(source_id, buf, &parsed_attack) != 0) {
            continue;
        }

        if (parsed_attack.source != 0 && procauth_isauthoritative(
                    parsed_attack.service, parsed_attack.source) == -1) {
            sshguard_log(LOG_NOTICE,
                    "Ignoring message from pid %d on service %d",
                    parsed_attack.source, parsed_attack.service);
            continue;
        }

        sshguard_log(LOG_DEBUG, "Attack from %s on service %d with danger %u",
                parsed_attack.address.value, parsed_attack.service,
                parsed_attack.dangerousness);
        report_address(parsed_attack);
    }

    if (!opts.has_polled_files && feof(stdin)) {
        sshguard_log(LOG_NOTICE, "Received EOF from stdin");
    } else {
        sshguard_log(LOG_ERR, "Unable to read any more log entries");
    }
}

static int read_log_line(char *restrict buf, sourceid_t *restrict source_id) {
    /* must fill buf, and return 0 for success and -1 for error */

    /* get logs from polled files ? */
    if (opts.has_polled_files) {
        /* logsuck_getline() reflects the 0/-1 codes already */
        return logsuck_getline(buf, MAX_LOGLINE_LEN, source_id);
    }

    /* otherwise, get logs from stdin */
    if (source_id != NULL) *source_id = 0;

    return (fgets(buf, MAX_LOGLINE_LEN, stdin) != NULL ? 0 : -1);
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
    pthread_mutex_lock(& list_mutex);
    tmpent = list_seek(& hell, & attack.address);
    pthread_mutex_unlock(& list_mutex);
    if (tmpent != NULL) {
        sshguard_log(LOG_WARNING, "%s: should already have been blocked",
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
        sshguard_log(LOG_DEBUG, "%s: first block (adding as offender)",
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
        for (unsigned int i = 0; i < offenderent->numhits; i++) {
            tmpent->pardontime *= 1.5;
        }
    }
    list_sort(& offenders, -1);

    sshguard_log(LOG_NOTICE, "%s: blocking for %lld secs (%u attacks in %lld secs, after %d abuses over %lld secs)",
            tmpent->attack.address.value, (long long)tmpent->pardontime,
            tmpent->numhits, (long long)(tmpent->whenlast - tmpent->whenfirst),
            offenderent->numhits,
            (long long)(offenderent->whenlast - offenderent->whenfirst));
    int ret = fw_block(attack.address.value,
            attack.address.kind, attack.service);
    if (ret != FWALL_OK) {
        sshguard_log(LOG_ERR, "fw: failed to block (%d)", ret);
    }

    /* append blocked attacker to the blocked list, and remove it from the pending list */
    pthread_mutex_lock(& list_mutex);
    list_append(& hell, tmpent);
    pthread_mutex_unlock(& list_mutex);
    assert(list_locate(& limbo, tmpent) >= 0);
    list_delete_at(& limbo, list_locate(& limbo, tmpent));
}

static void purge_limbo_stale(void) {
    sshguard_log(LOG_DEBUG, "Purging old attackers");
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

static void *pardonBlocked() {
    time_t now;
    attacker_t *tmpel;
    int ret;

    while (1) {
        /* wait some time, at most opts.pardon_threshold/3 + 1 sec */
        sleep(1 + ((unsigned int)rand() % (1+opts.pardon_threshold/2)));
        now = time(NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ret);
        pthread_mutex_lock(& list_mutex);

        for (unsigned int pos = 0; pos < list_size(&hell); pos++) {
            tmpel = list_get_at(&hell, pos);
            /* skip blacklisted hosts (pardontime = infinite/0) */
            if (tmpel->pardontime == 0) continue;
            /* process hosts with finite pardon time */
            if (now - tmpel->whenlast > tmpel->pardontime) {
                /* pardon time passed, release block */
                sshguard_log(LOG_INFO, "%s: unblocking after %lld secs",
                        tmpel->attack.address.value,
                        (long long)(now - tmpel->whenlast));
                ret = fw_release(tmpel->attack.address.value, tmpel->attack.address.kind, tmpel->attack.service);
                if (ret != FWALL_OK) {
                    sshguard_log(LOG_ERR, "fw: failed to unblock (%d)", ret);
                }
                list_delete_at(&hell, pos);
                free(tmpel);
                /* element removed, next element is at current index (don't step pos) */
                pos--;
            }
        }
        
        pthread_mutex_unlock(& list_mutex);
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ret);
        pthread_testcancel();
    }

    pthread_exit(NULL);
    return NULL;
}

static void finishup(void) {
    sshguard_log(LOG_INFO, "Exiting on %s",
            exit_sig == SIGHUP ? "SIGHUP" : "signal");

    if (fw_flush() != FWALL_OK) {
        sshguard_log(LOG_ERR, "fw: failed to flush blocked addresses");
    }

    if (opts.has_polled_files) {
        logsuck_fin();
    }

    fw_fin();
    whitelist_fin();
    procauth_fin();
    sshguard_log_fin();
}

static void sigfin_handler(int sig) {
    exit_sig = sig;
    exit(0);
}

static void process_blacklisted_addresses() {
    list_t *blacklist;
    const char **addresses;         /* NULL-terminated array of (string) addresses to block:  char *addresses[]  */
    int *restrict service_codes;    /* array of service codes resp to the given addresses */

    if (opts.blacklist_filename == NULL) {
        // Return if blacklisting is not enabled.
        return;
    }

    blacklist = blacklist_load(opts.blacklist_filename);
    if (blacklist == NULL) {
        perror("Could not open blacklist");
        sshguard_log(LOG_ERR, "blacklist: could not open %s",
                opts.blacklist_filename);
        exit(66);
    }

    /* blacklist enabled */
    size_t num_blacklisted = list_size(blacklist);
    sshguard_log(LOG_INFO, "blacklist: blocking %lu addresses",
            (long unsigned int)num_blacklisted);
    /* prepare to call fw_block_list() to block in bulk */
    /* two runs, one for each address kind (but allocate arrays once) */
    addresses = (const char **)malloc(sizeof(const char *) * (num_blacklisted+1));
    service_codes = (int *restrict)malloc(sizeof(int) * num_blacklisted);
    int addrkind;
    for (addrkind = ADDRKIND_IPv4; addrkind != -1; addrkind = (addrkind == ADDRKIND_IPv4 ? ADDRKIND_IPv6 : -1)) {
        /* extract from blacklist only addresses (and resp. codes) of type addrkind */
        int i = 0;
        list_iterator_start(blacklist);
        while (list_iterator_hasnext(blacklist)) {
            const attacker_t *bl_attacker = list_iterator_next(blacklist);
            if (bl_attacker->attack.address.kind != addrkind)
                continue;

            // Trim trailing newline from strchr().
            char *time_str = ctime(&bl_attacker->whenlast);
            char *newline = strchr(time_str, '\n');
            assert(newline != NULL);
            *newline = '\0';
            sshguard_log(LOG_DEBUG,
                    "blacklist: loaded %s (ip%d) on service %d: %s",
                    bl_attacker->attack.address.value,
                    bl_attacker->attack.address.kind,
                    bl_attacker->attack.service, time_str);
            addresses[i] = bl_attacker->attack.address.value;
            service_codes[i] = bl_attacker->attack.service;
            ++i;
        }
        list_iterator_stop(blacklist);
        if (i == 0) continue;
        /* terminate array list */
        addresses[i] = NULL;
        /* do block addresses of this kind */
        if (fw_block_list(addresses, addrkind, service_codes) != FWALL_OK) {
            sshguard_log(LOG_ERR, "blacklist: failed to block addresses");
        }
    }
    /* free temporary arrays */
    free(addresses);
    free(service_codes);
}

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
