#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "block_manager.h"
#include "simclist.h"
#include "sshguard_blacklist.h"
#include "sshguard_log.h"
#include "sshguard_options.h"
#include "heap.h"

/* Contains addresses currently blocked, not including blacklisted ones */
static min_heap_t block_store;

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

static void *release_thread_loop(void *unused) {
    const attacker_t *expired_attacker;
    struct timespec ts;
    time_t now;
    int rc;

    if (pthread_mutex_lock(&block_store.lock) != 0) {
        sshguard_log(LOG_ERR, "Could not lock mutex");
        exit(1);
    }

    while (true) {
        while (block_store.size == 0)
            pthread_cond_wait(&block_store.cond, &block_store.lock);

        ts.tv_sec = block_store.array[0].expire_time;
        ts.tv_nsec = 0;

        rc = pthread_cond_timedwait(&block_store.cond, &block_store.lock, &ts);
        if (rc == ETIMEDOUT) {
            now = time(NULL);
            while (block_store.size > 0 && block_store.array[0].expire_time <= now) {
                expired_attacker = heap_extract_min(&block_store);
                sshguard_log(LOG_NOTICE, "%s: unblocking after %lld secs",
                             expired_attacker->attack.address.value,
                             (long long)(now - expired_attacker->whenlast));
                fw_release(&expired_attacker->attack);
            }
        }
    }

    pthread_mutex_unlock(&block_store.lock);
    return NULL;
}

void block_manager_start(void) {
    pthread_t tid;

    heap_init(&block_store);

    if (pthread_create(&tid, NULL, release_thread_loop, NULL) != 0) {
        perror("pthread_create()");
        exit(2);
    }

    pthread_detach(tid);
}

bool block_store_contains(const sshg_address_t *target) {
    pthread_mutex_lock(&block_store.lock);
    bool ret = heap_contains(&block_store, target);
    pthread_mutex_unlock(&block_store.lock);
    return ret;
}

void block_store_add(const attacker_t *attacker) {
    fw_block(&attacker->attack);

    if (attacker->pardontime == INFINITE_PARDON)
        return;

    pthread_mutex_lock(&block_store.lock);
    heap_insert(&block_store, attacker);
    pthread_mutex_unlock(&block_store.lock);
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
