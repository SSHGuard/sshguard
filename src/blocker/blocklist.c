#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "blocklist.h"
#include "simclist.h"
#include "sshguard_blacklist.h"
#include "sshguard_log.h"
#include "sshguard_options.h"

/* list of addresses currently blocked (offenders) */
static list_t hell;

/* mutex against races between insertions and pruning of lists */
static pthread_mutex_t list_mutex;

unsigned int fw_block_subnet_size(int inet_family) {
    if (inet_family == 6) {
      return opts.subnet_ipv6;
    } else if (inet_family == 4) {
      return opts.subnet_ipv4;
    }

    assert(0);
}

static void fw_block(const attack_t *attack) {
    unsigned int subnet_size = fw_block_subnet_size(attack->address.kind);

    printf("block %s %d %u\n", attack->address.value, attack->address.kind, subnet_size);
    fflush(stdout);
}

static void fw_release(const attack_t *attack) {
    unsigned int subnet_size = fw_block_subnet_size(attack->address.kind);

    printf("release %s %d %u\n", attack->address.value, attack->address.kind, subnet_size);
    fflush(stdout);
}

static void unblock_expired() {
    attacker_t *tmpel;
    int ret;
    time_t now = time(NULL);

    pthread_testcancel();
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ret);
    pthread_mutex_lock(&list_mutex);

    for (unsigned int pos = 0; pos < list_size(&hell); pos++) {
        tmpel = list_get_at(&hell, pos);
        /* skip blacklisted hosts (pardontime = infinite/0) */
        if (tmpel->pardontime == 0)
            continue;
        /* process hosts with finite pardon time */
        if (now - tmpel->whenlast > tmpel->pardontime) {
            /* pardon time passed, release block */
            sshguard_log(LOG_DEBUG, "%s: unblocking after %lld secs",
                         tmpel->attack.address.value,
                         (long long)(now - tmpel->whenlast));
            fw_release(&tmpel->attack);
            list_delete_at(&hell, pos);
            free(tmpel);
            /* element removed, next element is at current index (don't step
             * pos) */
            pos--;
        }
    }

    pthread_mutex_unlock(&list_mutex);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ret);
    pthread_testcancel();
}

static void *unblock_loop() {
    while (1) {
        /* wait some time, at most opts.pardon_threshold/3 + 1 sec */
        sleep(1 + ((unsigned int)rand() % (1 + opts.pardon_threshold / 2)));
        unblock_expired();
    }

    pthread_exit(NULL);
    return NULL;
}

void blocklist_init() {
    pthread_t tid;
    list_init(&hell);
    list_attributes_seeker(&hell, attack_addr_seeker);

    /* start thread for purging stale blocked addresses */
    pthread_mutex_init(&list_mutex, NULL);
    if (pthread_create(&tid, NULL, unblock_loop, NULL) != 0) {
        perror("pthread_create()");
        exit(2);
    }
}

bool blocklist_contains(attack_t attack) {
    attacker_t *tmpent = NULL;
    pthread_mutex_lock(&list_mutex);
    tmpent = list_seek(&hell, &attack.address);
    pthread_mutex_unlock(&list_mutex);
    return tmpent != NULL;
}

void blocklist_add(attacker_t *tmpent) {
    fw_block(&tmpent->attack);

    pthread_mutex_lock(&list_mutex);
    list_append(&hell, tmpent);
    pthread_mutex_unlock(&list_mutex);
}

static void block_list(list_t *list) {
    list_iterator_start(list);
    while (list_iterator_hasnext(list)) {
        attacker_t *next = list_iterator_next(list);
        fw_block(&next->attack);
    }
    list_iterator_stop(list);
}

void blacklist_load_and_block() {
    list_t *blacklist = blacklist_load(opts.blacklist_filename);
    if (blacklist == NULL) {
        sshguard_log(LOG_ERR, "blacklist: could not open %s: %m",
                     opts.blacklist_filename);
        exit(66);
    }

    sshguard_log(LOG_INFO, "blacklist: blocking %u addresses",
                 (unsigned int)list_size(blacklist));
    block_list(blacklist);
}
