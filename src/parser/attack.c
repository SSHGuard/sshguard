#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include "attack.h"
#include "sshguard_log.h"

int attackt_whenlast_comparator(const void *a, const void *b) {
    const attacker_t *aa = (const attacker_t *)a;
    const attacker_t *bb = (const attacker_t *)b;
    return ((aa->whenlast > bb->whenlast) - (aa->whenlast < bb->whenlast));
}

void attackerinit(attacker_t *restrict ipe,
                                const attack_t *restrict attack) {
    assert(ipe != NULL && attack != NULL);
    strcpy(ipe->attack.address.value, attack->address.value);
    ipe->attack.address.kind = attack->address.kind;
    ipe->attack.service = attack->service;
    ipe->whenfirst = ipe->whenlast = time(NULL);
    ipe->numhits = 1;
    ipe->cumulated_danger = attack->dangerousness;
}

int attack_addr_seeker(const void *el, const void *key) {
    const sshg_address_t *adr = (const sshg_address_t *)key;
    const attacker_t *atk = (const attacker_t *)el;

    assert(atk != NULL && adr != NULL);
    if (atk->attack.address.kind != adr->kind) return 0;
    return (strcmp(atk->attack.address.value, adr->value) == 0);
}

int attack_from_hostname(attack_t *attack, const char *name) {
    struct addrinfo addrinfo_hints;
    struct addrinfo *addrinfo_result;
    int res;

    /* look up IPv4 first */
    memset(&addrinfo_hints, 0x00, sizeof(addrinfo_hints));
    addrinfo_hints.ai_family = AF_INET;
    res = getaddrinfo(name, NULL, &addrinfo_hints, &addrinfo_result);
    if (res == 0) {
        struct sockaddr_in *foo4;
        /* pick the first (IPv4) result address and return */
        attack->address.kind = ADDRKIND_IPv4;
        foo4 = (struct sockaddr_in *)(addrinfo_result->ai_addr);
        if (inet_ntop(AF_INET, &foo4->sin_addr, attack->address.value,
                      sizeof(attack->address.value)) == NULL) {
            freeaddrinfo(addrinfo_result);
            sshguard_log(LOG_ERR, "Unable to interpret resolution result as "
                                  "IPv4 address: %m. Giving up entry.");
            return false;
        }
    } else {
        /* try IPv6 */
        addrinfo_hints.ai_family = AF_INET6;
        res = getaddrinfo(name, NULL, &addrinfo_hints, &addrinfo_result);
        if (res == 0) {
            struct sockaddr_in6 *foo6;
            /* pick the first (IPv6) result address and return */
            attack->address.kind = ADDRKIND_IPv6;
            foo6 = (struct sockaddr_in6 *)(addrinfo_result->ai_addr);
            if (inet_ntop(AF_INET6, &foo6->sin6_addr, attack->address.value,
                          sizeof(attack->address.value)) == NULL) {
                sshguard_log(LOG_ERR, "Unable to interpret resolution result "
                                      "as IPv6 address: %m. Giving up entry.");
                freeaddrinfo(addrinfo_result);
                return false;
            }
        } else {
            sshguard_log(LOG_ERR, "Could not resolv '%s' in neither of "
                                  "IPv{4,6}. Giving up entry.",
                         name);
            return false;
        }
    }

    sshguard_log(LOG_INFO, "Successfully resolved '%s' --> %d:'%s'.", name,
                 attack->address.kind, attack->address.value);
    freeaddrinfo(addrinfo_result);
    return true;
}
