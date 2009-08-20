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


/* fill an attacker_t structure for usage */
static inline void attackerinit(attacker_t *restrict ipe, const attack_t *restrict attack);
/* comparison operator for sorting offenders list */
static int attackt_whenlast_comparator(const void *a, const void *b);

#ifdef EINTR
/* get line unaffected by interrupts */
char *safe_fgets(char *restrict s, int size, FILE *restrict stream);
#endif
/* handler for termination-related signals */
void sigfin_handler(int signo);
/* handler for suspension/resume signals */
void sigstpcont_handler(int signo);
/* called at exit(): flush blocked addresses and finalize subsystems */
void finishup(void);

/* handle an attack: addr is the author, addrkind its address kind, service the attacked service code */
void report_address(attack_t attack);
/* cleanup false-alarm attackers from limbo list (ones with too few attacks in too much time) */
void purge_limbo_stale(void);
/* release blocked attackers after their penalty expired */
void *pardonBlocked(void *par);


int main(int argc, char *argv[]) {
    pthread_t tid;
    int retv;
    char buf[MAX_LOGLINE_LEN];
    /* list of addresses that have been blacklisted */
    list_t *blacklist = NULL;
    
    /* initializations */
    suspended = 0;

    /* pending, blocked, and offender address lists */
    list_init(&limbo);
    list_attributes_seeker(& limbo, seeker_addr);
    list_init(&hell);
    list_attributes_seeker(& hell, seeker_addr);
    list_init(&offenders);
    list_attributes_seeker(& offenders, seeker_addr);
    list_attributes_comparator(& offenders, attackt_whenlast_comparator);

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

    /* whitelist localhost */
    if (whitelist_add("127.0.0.1") != 0) {
        fprintf(stderr, "Could not whitelist localhost. terminating...\n");
        exit(1);
    }

    whitelist_conf_fin();

    /* logging system */
    sshguard_log_init(opts.debugging);

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

    /* if blacklist enabled, block blacklisted addresses */
    if (opts.blacklist_filename != NULL) {
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
        sshguard_log(LOG_INFO, "Blacklist loaded, %d addresses.", list_size(blacklist));
        for (retv = 0; retv < list_size(blacklist); retv++) {
            attacker_t *bl_attacker = list_get_at(blacklist, retv);
            assert(bl_attacker != NULL);
            sshguard_log(LOG_DEBUG, "Loaded from blacklist (%d): '%s:%d', service %d, last seen %s.", retv, bl_attacker->attack.address.value, bl_attacker->attack.address.kind, bl_attacker->attack.service, ctime(& bl_attacker->whenlast));
            fw_block(bl_attacker->attack.address.value, bl_attacker->attack.address.kind, bl_attacker->attack.service);
        }
        list_destroy(blacklist);
        free(blacklist);
        blacklist = NULL;


        blacklist = blacklist_load(opts.blacklist_filename);

    }

    /* set opts.debugging value for parser/scanner ... */
    yydebug = opts.debugging;
    yy_flex_debug = opts.debugging;
    
    /* start thread for purging stale blocked addresses */
    if (pthread_create(&tid, NULL, pardonBlocked, NULL) != 0) {
        perror("pthread_create()");
        exit(2);
    }


    /* initialization successful */
    
    sshguard_log(LOG_INFO, "Started successfully [(a,p,s)=(%u, %u, %u)], now ready to scan.", \
            opts.abuse_threshold, (unsigned int)opts.pardon_threshold, (unsigned int)opts.stale_threshold);


#ifdef EINTR
    while (safe_fgets(buf, MAX_LOGLINE_LEN, stdin) != NULL) {
#else
    while (fgets(buf, MAX_LOGLINE_LEN, stdin) != NULL) {
#endif

        if (suspended) continue;

        retv = parse_line(buf);
        if (retv != 0) {
            /* sshguard_log(LOG_DEBUG, "Skip line '%s'", buf); */
            continue;
        }

        /* extract the IP address */
        sshguard_log(LOG_DEBUG, "Matched address %s:%d attacking service %d", parsed_attack.address.value, parsed_attack.address.kind, parsed_attack.service);
       
        /* report IP */
        report_address(parsed_attack);
    }

    /* let exit() call finishup() */
    exit(0);
}

#ifdef EINTR
char *safe_fgets(char *restrict s, int size, FILE *restrict stream) {
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
void report_address(attack_t attack) {
    attacker_t *tmpent = NULL;
    attacker_t *offenderent;
    int ret;

    assert(attack.address.value != NULL);

    /* clean list from stale entries */
    purge_limbo_stale();

    /* protected address? */
    if (whitelist_match(attack.address.value, attack.address.kind)) {
        sshguard_log(LOG_INFO, "Pass over address %s because it's been whitelisted.", attack.address.value);
        return;
    }
    
    /* search entry in list */
    tmpent = list_seek(& limbo, attack.address.value);

    if (tmpent == NULL) { /* entry not already in list, add it */
        /* otherwise: insert the new item */
        tmpent = malloc(sizeof(attacker_t));
        attackerinit(tmpent, & attack);
        list_append(&limbo, tmpent);
    }


    /* otherwise, the entry was already existing */
    /* update last hit */
    tmpent->whenlast = time(NULL);
    tmpent->numhits++;
    if (tmpent->numhits < opts.abuse_threshold) {
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
        sshguard_log(LOG_DEBUG, "First sight of offender '%s:%d', adding to offenders list.", tmpent->attack.address.value, tmpent->attack.address.kind);
        offenderent = (attacker_t *)malloc(sizeof(attacker_t));
        memcpy(offenderent, tmpent, sizeof(attacker_t));
        offenderent->numhits = 1;
        list_prepend(& offenders, offenderent);
        assert(! list_empty(& offenders));
#if 0
        /* we assume that the list is already sorted by decreasing last-attack time */
        /* prune list */
        if (list_size(& offenders) > MAX_OFFENDER_ITEMS) {
            list_delete_range(& offenders, MAX_OFFENDER_ITEMS, list_size(& offenders)-1);
        }
#endif
    } else {
        /* this is a previous offender */
        offenderent->numhits++;
        offenderent->whenlast = tmpent->whenlast;

        if (offenderent->numhits >= opts.blacklist_threshold) {
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
                        sshguard_log(LOG_NOTICE, "Offender '%s:%d' seen %d times (threshold %d) -> blacklisted.",
                                tmpent->attack.address.value, tmpent->attack.address.kind, offenderent->numhits,
                                opts.blacklist_threshold);
                        if (blacklist_add(opts.blacklist_filename, offenderent) != 0) {
                            sshguard_log(LOG_ERR, "Could not blacklist address: %s", strerror(errno));
                        }
                        break;
                    default:    /* error while looking up */
                        sshguard_log(LOG_ERR, "Error while looking up '%s:%d' in blacklist '%s'.", attack.address.value, attack.address.kind, opts.blacklist_filename);
                }
            }
        } else {
            sshguard_log(LOG_INFO, "Offender '%s:%d' seen %d times.", tmpent->attack.address.value, tmpent->attack.address.kind, offenderent->numhits);
            /* compute blocking time wrt the "offensiveness" */
            for (ret = 0; ret < offenderent->numhits; ret++) {
                tmpent->pardontime *= 2;
            }
        }
    }
    list_sort(& offenders, -1);

    sshguard_log(LOG_NOTICE, "Blocking %s:%d for >%dsecs: %u failures over %u seconds.\n", tmpent->attack.address.value,
            tmpent->attack.address.kind, tmpent->pardontime, tmpent->numhits, tmpent->whenlast - tmpent->whenfirst);
    ret = fw_block(attack.address.value, attack.address.kind, attack.service);
    if (ret != FWALL_OK) sshguard_log(LOG_ERR, "Blocking command failed. Exited: %d", ret);

    /* append blocked attacker to the blocked list, and remove it from the pending list */
    list_append(&hell, tmpent);
    assert(list_locate(& limbo, tmpent) >= 0);
    list_delete_at(& limbo, list_locate(& limbo, tmpent));
}

static inline void attackerinit(attacker_t *restrict ipe, const attack_t *restrict attack) {
    assert(ipe != NULL && attack != NULL);
    strcpy(ipe->attack.address.value, attack->address.value);
    ipe->attack.address.kind = attack->address.kind;
    ipe->attack.service = attack->service;
    ipe->whenfirst = ipe->whenlast = time(NULL);
    ipe->numhits = 0;
}

void purge_limbo_stale(void) {
    attacker_t *tmpent;
    time_t now;
    unsigned int pos = 0;


    now = time(NULL);
    for (pos = 0; pos < list_size(&limbo); pos++) {
        tmpent = list_get_at(&limbo, pos);
        if (now - tmpent->whenfirst > opts.stale_threshold)
            list_delete_at(&limbo, pos);
    }
}

void *pardonBlocked(void *par) {
    time_t now;
    attacker_t *tmpel;
    int ret, pos;


    srandom(time(NULL));

    while (1) {
        /* wait some time, at most opts.pardon_threshold/3 + 1 sec */
        sleep(1 + (random() % (1+opts.pardon_threshold/2)));
        now = time(NULL);
        tmpel = list_get_at(&hell, 0);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ret);

        for (pos = 0; pos < list_size(& hell); pos++) {
            tmpel = list_get_at(&hell, pos);
            /* skip blacklisted hosts (pardontime = infinite/0) */
            if (tmpel->pardontime == 0) continue;
            /* process hosts with finite pardon time */
            if (now - tmpel->whenlast > tmpel->pardontime) {
                /* pardon time passed, release block */
                sshguard_log(LOG_INFO, "Releasing %s after %u seconds.\n", tmpel->attack.address.value, now - tmpel->whenlast);
                ret = fw_release(tmpel->attack.address.value, tmpel->attack.address.kind, tmpel->attack.service);
                if (ret != FWALL_OK) sshguard_log(LOG_ERR, "Release command failed. Exited: %d", ret);
                list_delete_at(&hell, 0);
                free(tmpel);
                /* element removed, next element is at current index (don't step pos) */
                pos--;
            }
        }
        
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ret);
        pthread_testcancel();
    }

    pthread_exit(NULL);
    return NULL;
}

/* finalization routine */
void finishup(void) {
    /* flush blocking rules */
    sshguard_log(LOG_INFO, "Got exit signal, flushing blocked addresses and exiting...");
    fw_flush();
    if (fw_fin() != FWALL_OK) sshguard_log(LOG_ERR, "Cound not finalize firewall.");
    if (whitelist_fin() != 0) sshguard_log(LOG_ERR, "Could not finalize the whitelisting system.");
    if (procauth_fin() != 0) sshguard_log(LOG_ERR, "Could not finalize the process authorization subsystem.");
    sshguard_log_fin();
}

void sigfin_handler(int signo) {
    /* let exit() call finishup() */
    exit(0);
}

void sigstpcont_handler(int signo) {
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

