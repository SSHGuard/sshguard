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
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>

#include <simclist.h>


/* subsystem for parsing log entries, notably parse_line() */
#include "parser.h"

/* logging subsystem, sshguard_log() */
#include "sshguard_log.h"
/* functions for getting user's preferences */
#include "sshguard_options.h"
/* constant definitions for address types */
#include "sshguard_addresskind.h"
/* functions for managing whitelist (addresses not to block): whitelist_*() */
#include "sshguard_whitelist.h"
/* functions for reading and updating the blacklist (addresses to block and never release): blacklist_*() */
#include "sshguard_blacklist.h"
/* functions for log messages verification: procauth_*() */
#include "sshguard_procauth.h"
/* functions for controlling the underlying firewall: fw_*() */
#include "sshguard_fw.h"
/* seeker functions for lists */
#include "seekers.h"
/* data types for tracking attacks (attack_t, attacker_t etc) */
#include "sshguard_attack.h"
/* subsystem for polling multiple log files and getting log entries */
#include "sshguard_logsuck.h"

#include "sshguard.h"

#define MAX_LOGLINE_LEN     1000

/* switch from 0 (normal) to 1 (suspended) with SIGTSTP and SIGCONT respectively */
int suspended;


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

/* global debugging flag */
int sshg_debugging = 0;

/* mutex against races between insertions and pruning of lists */
pthread_mutex_t list_mutex;


/* fill an attacker_t structure for usage */
static inline void attackerinit(attacker_t *restrict ipe, const attack_t *restrict attack);
/* comparison operator for sorting offenders list */
static int attackt_whenlast_comparator(const void *a, const void *b);

/* get log lines in here. Hide the actual source and the method. Fill buf up
 * to buflen chars, return 0 for success, -1 for failure */
static int read_log_line(char *restrict buf, size_t buflen, bool from_last_source, sourceid_t *restrict source_id);
#ifdef EINTR
/* get line unaffected by interrupts */
static char *safe_fgets(char *restrict s, int size, FILE *restrict stream);
#endif
/* handler for termination-related signals */
static void sigfin_handler(int signo);
/* handler for suspension/resume signals */
static void sigstpcont_handler(int signo);
/* called at exit(): flush blocked addresses and finalize subsystems */
static void finishup(void);

/* load blacklisted addresses and block them (if blacklist enabled) */
static void process_blacklisted_addresses();
/* handle an attack: addr is the author, addrkind its address kind, service the attacked service code */
static void report_address(attack_t attack);
/* cleanup false-alarm attackers from limbo list (ones with too few attacks in too much time) */
static void purge_limbo_stale(void);
/* release blocked attackers after their penalty expired */
static void *pardonBlocked(void *par);

/* create or destroy my own pidfile */
static int my_pidfile_create();
static void my_pidfile_destroy();


int main(int argc, char *argv[]) {
    pthread_t tid;
    int retv;
    sourceid_t source_id;
    char buf[MAX_LOGLINE_LEN];
    

    /* initializations */
    srand(time(NULL));
    suspended = 0;
    sshg_debugging = (getenv("SSHGUARD_DEBUG") != NULL);

    /* pending, blocked, and offender address lists */
    list_init(&limbo);
    list_attributes_seeker(& limbo, seeker_addr);
    list_init(&hell);
    list_attributes_seeker(& hell, seeker_addr);
    list_init(&offenders);
    list_attributes_seeker(& offenders, seeker_addr);
    list_attributes_comparator(& offenders, attackt_whenlast_comparator);
    pthread_mutex_init(& list_mutex, NULL);


    /* logging system */
    sshguard_log_init(sshg_debugging);

    /* whitelisting system */
    if (whitelist_init() != 0 || whitelist_conf_init() != 0) {
        fprintf(stderr, "Could not nitialize the whitelist engine.\n");
        exit(1);
    }

    /* process authorization system */
    if (procauth_init() != 0) {
        fprintf(stderr, "Could not initialize the process authorization subsystem.");
        exit(1);
    }

    /* parsing the command line */
    if (get_options_cmdline(argc, argv) != 0) {
        exit(1);
    }

    /* create pidfile, if requested */
    if (opts.my_pidfile != NULL) {
        if (my_pidfile_create() != 0)
            exit(1);
        atexit(my_pidfile_destroy);
    }

    /* whitelist localhost */
    if (whitelist_add("127.0.0.1") != 0) {
        fprintf(stderr, "Could not whitelist localhost. Terminating...\n");
        exit(1);
    }

    whitelist_conf_fin();

    /* address blocking system */
    if (fw_init() != FWALL_OK) {
        sshguard_log(LOG_CRIT, "Could not init firewall. Terminating.\n");
        fprintf(stderr, "Could not init firewall. Terminating.\n");
        exit(1);
    }


    /* set finalization routine */
    atexit(finishup);

    /* suspension signals */
    signal(SIGTSTP, sigstpcont_handler);
    signal(SIGCONT, sigstpcont_handler);

    /* termination signals */
    signal(SIGTERM, sigfin_handler);
    signal(SIGHUP, sigfin_handler);
    signal(SIGINT, sigfin_handler);

    /* load blacklisted addresses and block them (if requested) */
    process_blacklisted_addresses();

    /* set debugging value for parser/scanner ... */
    yydebug = sshg_debugging;
    yy_flex_debug = sshg_debugging;
    
    /* start thread for purging stale blocked addresses */
    if (pthread_create(&tid, NULL, pardonBlocked, NULL) != 0) {
        perror("pthread_create()");
        exit(2);
    }


    /* initialization successful */
    
    sshguard_log(LOG_INFO, "Started successfully [(a,p,s)=(%u, %u, %u)], now ready to scan.", \
            opts.abuse_threshold, (unsigned int)opts.pardon_threshold, (unsigned int)opts.stale_threshold);


    while (read_log_line(buf, MAX_LOGLINE_LEN, false, & source_id) == 0) {
        if (suspended) continue;

        retv = parse_line(source_id, buf);
        if (retv != 0) {
            /* sshguard_log(LOG_DEBUG, "Skip line '%s'", buf); */
            continue;
        }

        /* extract the IP address */
        sshguard_log(LOG_DEBUG, "Matched address %s:%d attacking service %d, dangerousness %u.", parsed_attack.address.value, parsed_attack.address.kind, parsed_attack.service, parsed_attack.dangerousness);
       
        /* report IP */
        report_address(parsed_attack);
    }

    /* let exit() call finishup() */
    exit(0);
}

static int read_log_line(char *restrict buf, size_t buflen, bool from_last_source, sourceid_t *restrict source_id) {
    /* must fill buf, and return 0 for success and -1 for error */

    /* get logs from polled files ? */
    if (opts.has_polled_files) {
        /* logsuck_getline() reflects the 0/-1 codes already */
        return logsuck_getline(buf, MAX_LOGLINE_LEN, from_last_source, source_id);
    }

    /* otherwise, get logs from stdin */
    if (source_id != NULL) *source_id = 0;

#ifdef EINTR
    return (safe_fgets(buf, MAX_LOGLINE_LEN, stdin) != NULL ? 0 : -1);
#else
    return (fgets(buf, MAX_LOGLINE_LEN, stdin) != NULL ? 0 : -1);
#endif
}

#ifdef EINTR
static char *safe_fgets(char *restrict s, int size, FILE *restrict stream) {
    char *restrict ret;

    do {
        clearerr(stream);
        ret = fgets(s, size, stream);
        if (ret != NULL)
            return s;
        if (errno != EINTR)
            return NULL;
    } while (ret == NULL && errno == EINTR);

    /* pretend we arrive here to make compiler happy */
    return NULL;
}
#endif


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
    int ret;

    assert(attack.address.value != NULL);

    /* clean list from stale entries */
    purge_limbo_stale();

    /* address already blocked? (can happen for 100 reasons) */
    pthread_mutex_lock(& list_mutex);
    tmpent = list_seek(& hell, & attack.address);
    pthread_mutex_unlock(& list_mutex);
    if (tmpent != NULL) {
        sshguard_log(LOG_INFO, "Asked to block '%s', which was already blocked to my account.", attack.address.value);
        return;
    }

    /* protected address? */
    if (whitelist_match(attack.address.value, attack.address.kind)) {
        sshguard_log(LOG_INFO, "Pass over address %s because it's been whitelisted.", attack.address.value);
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
        sshguard_log(LOG_DEBUG, "First abuse of '%s', adding to offenders list.", tmpent->attack.address.value);
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
    if (offenderent->cumulated_danger >= opts.blacklist_threshold) {
        /* this host must be blacklisted -- blocked and never unblocked */
        tmpent->pardontime = 0;

        /* insert in the blacklisted db iff enabled */
        if (opts.blacklist_filename != NULL) {
            switch (blacklist_lookup_address(opts.blacklist_filename, & offenderent->attack.address)) {
                case 1:     /* in blacklist */
                    /* do nothing */
                    break;
                case 0:     /* not in blacklist */
                    /* add it */
                    sshguard_log(LOG_NOTICE, "Offender '%s:%d' scored %d danger in %u abuses (threshold %u) -> blacklisted.",
                            offenderent->attack.address.value, offenderent->attack.address.kind,
                            offenderent->cumulated_danger, offenderent->numhits,
                            opts.blacklist_threshold);
                    if (blacklist_add(opts.blacklist_filename, offenderent) != 0) {
                        sshguard_log(LOG_ERR, "Could not blacklist offender: %s", strerror(errno));
                    }
                    break;
                default:    /* error while looking up */
                    sshguard_log(LOG_ERR, "Error while looking up '%s:%d' in blacklist '%s'.", attack.address.value, attack.address.kind, opts.blacklist_filename);
            }
        }
    } else {
        sshguard_log(LOG_INFO, "Offender '%s:%d' scored %u danger in %u abuses.", tmpent->attack.address.value, tmpent->attack.address.kind, offenderent->cumulated_danger, offenderent->numhits);
        /* compute blocking time wrt the "offensiveness" */
        for (ret = 0; ret < offenderent->numhits; ret++) {
            tmpent->pardontime *= 1.5;
        }
    }
    list_sort(& offenders, -1);

    sshguard_log(LOG_NOTICE, "Blocking %s:%d for >%lldsecs: %u danger in %u attacks over %lld seconds (all: %ud in %d abuses over %llds).\n",
            tmpent->attack.address.value, tmpent->attack.address.kind, (long long int)tmpent->pardontime,
            tmpent->cumulated_danger, tmpent->numhits, (long long int)(tmpent->whenlast - tmpent->whenfirst),
            offenderent->cumulated_danger, offenderent->numhits, (long long int)(offenderent->whenlast - offenderent->whenfirst));
    ret = fw_block(attack.address.value, attack.address.kind, attack.service);
    if (ret != FWALL_OK) sshguard_log(LOG_ERR, "Blocking command failed. Exited: %d", ret);

    /* append blocked attacker to the blocked list, and remove it from the pending list */
    pthread_mutex_lock(& list_mutex);
    list_append(& hell, tmpent);
    pthread_mutex_unlock(& list_mutex);
    assert(list_locate(& limbo, tmpent) >= 0);
    list_delete_at(& limbo, list_locate(& limbo, tmpent));
}

static inline void attackerinit(attacker_t *restrict ipe, const attack_t *restrict attack) {
    assert(ipe != NULL && attack != NULL);
    strcpy(ipe->attack.address.value, attack->address.value);
    ipe->attack.address.kind = attack->address.kind;
    ipe->attack.service = attack->service;
    ipe->whenfirst = ipe->whenlast = time(NULL);
    ipe->numhits = 1;
    ipe->cumulated_danger = attack->dangerousness;
}

static void purge_limbo_stale(void) {
    attacker_t *tmpent;
    time_t now;
    unsigned int pos = 0;


    sshguard_log(LOG_DEBUG, "Purging stale attackers.");
    now = time(NULL);
    for (pos = 0; pos < list_size(&limbo); pos++) {
        tmpent = list_get_at(&limbo, pos);
        if (now - tmpent->whenfirst > opts.stale_threshold)
            list_delete_at(&limbo, pos);
    }
}

static void *pardonBlocked(void *par) {
    time_t now;
    attacker_t *tmpel;
    int ret, pos;


    while (1) {
        /* wait some time, at most opts.pardon_threshold/3 + 1 sec */
        sleep(1 + ((unsigned int)rand() % (1+opts.pardon_threshold/2)));
        now = time(NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ret);
        pthread_mutex_lock(& list_mutex);

        for (pos = 0; pos < list_size(& hell); pos++) {
            tmpel = list_get_at(&hell, pos);
            /* skip blacklisted hosts (pardontime = infinite/0) */
            if (tmpel->pardontime == 0) continue;
            /* process hosts with finite pardon time */
            if (now - tmpel->whenlast > tmpel->pardontime) {
                /* pardon time passed, release block */
                sshguard_log(LOG_INFO, "Releasing %s after %lld seconds.\n", tmpel->attack.address.value, (long long int)(now - tmpel->whenlast));
                ret = fw_release(tmpel->attack.address.value, tmpel->attack.address.kind, tmpel->attack.service);
                if (ret != FWALL_OK) sshguard_log(LOG_ERR, "Release command failed. Exited: %d", ret);
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

/* finalization routine */
static void finishup(void) {
    /* flush blocking rules */
    sshguard_log(LOG_INFO, "Got exit signal, flushing blocked addresses and exiting...");
    fw_flush();
    if (fw_fin() != FWALL_OK) sshguard_log(LOG_ERR, "Cound not finalize firewall.");
    if (whitelist_fin() != 0) sshguard_log(LOG_ERR, "Could not finalize the whitelisting system.");
    if (procauth_fin() != 0) sshguard_log(LOG_ERR, "Could not finalize the process authorization subsystem.");
    if (opts.has_polled_files) {
        if (logsuck_fin() != 0) sshguard_log(LOG_ERR, "Could not finalize the log polling subsystem.");
    }
    sshguard_log_fin();
}

static void sigfin_handler(int signo) {
    /* let exit() call finishup() */
    exit(0);
}

static void sigstpcont_handler(int signo) {
    /* update "suspended" status */
    switch (signo) {
        case SIGTSTP:
            suspended = 1;
            sshguard_log(LOG_NOTICE, "Got STOP signal, suspending activity.");
            break;
        case SIGCONT:
            suspended = 0;
            sshguard_log(LOG_NOTICE, "Got CONTINUE signal, resuming activity.");
            break;
    }
}

static int attackt_whenlast_comparator(const void *a, const void *b) {
    const attacker_t *aa = (const attacker_t *)a;
    const attacker_t *bb = (const attacker_t *)b;

    return ((aa->whenlast > bb->whenlast) - (aa->whenlast < bb->whenlast));
}

static void process_blacklisted_addresses() {
    list_t *blacklist;
    const char **addresses;         /* NULL-terminated array of (string) addresses to block:  char *addresses[]  */
    int *restrict service_codes;    /* array of service codes resp to the given addresses */
    int i;


    /* if blacklist enabled, block blacklisted addresses */
    if (opts.blacklist_filename == NULL)
        return;

    blacklist = blacklist_load(opts.blacklist_filename);
    if (blacklist == NULL) {
        sshguard_log(LOG_NOTICE, "Blacklist file '%s' doesn't exist, I'll create it for you.\n", opts.blacklist_filename);
        if (blacklist_create(opts.blacklist_filename) != 0) {
            /* write to both destinations to make sure the user notice it */
            fprintf(stderr, "Unable to create a blacklist file at '%s'! Terminating.\n", opts.blacklist_filename);
            sshguard_log(LOG_CRIT, "Unable to create a blacklist file at '%s'! Terminating.\n", opts.blacklist_filename);
            exit(1);
        }
        blacklist = blacklist_load(opts.blacklist_filename);
    }

    /* blacklist enabled */
    assert(blacklist != NULL);
    size_t num_blacklisted = list_size(blacklist);
    sshguard_log(LOG_INFO, "Blacklist loaded, blocking %lu addresses.", (long unsigned int)num_blacklisted);
    /* prepare to call fw_block_list() to block in bulk */
    /* two runs, one for each address kind (but allocate arrays once) */
    addresses = (const char **)malloc(sizeof(const char *) * (num_blacklisted+1));
    service_codes = (int *restrict)malloc(sizeof(int) * num_blacklisted);
    int addrkind;
    for (addrkind = ADDRKIND_IPv4; addrkind != -1; addrkind = (addrkind == ADDRKIND_IPv4 ? ADDRKIND_IPv6 : -1)) {
        /* extract from blacklist only addresses (and resp. codes) of type addrkind */
        i = 0;
        list_iterator_start(blacklist);
        while (list_iterator_hasnext(blacklist)) {
            const attacker_t *bl_attacker = list_iterator_next(blacklist);
            if (bl_attacker->attack.address.kind != addrkind)
                continue;
            sshguard_log(LOG_DEBUG, "Loaded from blacklist (%d): '%s:%d', service %d, last seen %s.", i,
                    bl_attacker->attack.address.value, bl_attacker->attack.address.kind, bl_attacker->attack.service,
                    ctime(& bl_attacker->whenlast));
            addresses[i] = bl_attacker->attack.address.value;
            service_codes[i] = bl_attacker->attack.service;
            ++i;
        }
        list_iterator_stop(blacklist);
        /* terminate array list */
        addresses[i] = NULL;
        /* do block addresses of this kind */
        if (fw_block_list(addresses, addrkind, service_codes) != FWALL_OK) {
            sshguard_log(LOG_CRIT, "While blocking blacklisted addresses, the firewall refused to block!");
        }
    }
    /* free temporary arrays */
    free(addresses);
    free(service_codes);
    /* free blacklist stuff */
    list_destroy(blacklist);
    free(blacklist);
}

static int my_pidfile_create() {
    FILE *p;
    
    p = fopen(opts.my_pidfile, "w");
    if (p == NULL) {
        sshguard_log(LOG_ERR, "Could not create pidfile '%s': %s.", opts.my_pidfile, strerror(errno));
        return -1;
    }
    fprintf(p, "%d\n", (int)getpid());
    fclose(p);

    return 0;
}

static void my_pidfile_destroy() {
    if (unlink(opts.my_pidfile) != 0)
        sshguard_log(LOG_ERR, "Could not remove pidfile '%s': %s.", opts.my_pidfile, strerror(errno));
}
