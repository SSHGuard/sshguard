#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "attack.h"
#include "sshguard_options.h"

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

unsigned int network_bits(sshg_address_t *address, enum subnet_mask_method method) {
    switch (method) {
    case MASK_SUBNET_SIZE:
        return (address->kind == ADDRKIND_IPv6) ? opts.subnet_ipv6 : opts.subnet_ipv4;
    default:
        return (address->kind == ADDRKIND_IPv6) ? 128 : 32;
    }
}

/**
 * Normalize an IP address by masking the host portion according to subnet size.
 * The address is modified in-place.
 *
 * @param address The address structure to normalize
 * @return 0 on success, -1 on error
 */
int normalize_address_by_subnet(sshg_address_t *address) {
    if (address == NULL) {
        return -1;
    }

    unsigned int subnet_size = network_bits(address, opts.mask_method);
    if (address->kind == ADDRKIND_IPv4) {
        if (subnet_size >= 32) {
            /* No masking needed for /32 */
            return 0;
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, address->value, &addr) != 1) {
            return -1;
        }

        /* Calculate mask: for /N, shift all-ones left by (32-N) bits */
        in_addr_t mask = htonl(UINT32_MAX << (32 - subnet_size));

        /* Apply mask */
        addr.s_addr &= mask;

        /* Convert back to string */
        if (inet_ntop(AF_INET, &addr, address->value, ADDRLEN) == NULL) {
            return -1;
        }
    } else if (address->kind == ADDRKIND_IPv6) {
        if (subnet_size >= 128) {
            /* No masking needed for /128 */
            return 0;
        }

        struct in6_addr addr, mask;
        if (inet_pton(AF_INET6, address->value, &addr) != 1) {
            return -1;
        }

        /* Create subnet mask from masklen */
        unsigned int full_bytes = subnet_size / 8;
        unsigned int bits_in_partial = subnet_size % 8;
        memset(mask.s6_addr, 0xFF, full_bytes);
        if (full_bytes < 16) {
            if (bits_in_partial > 0) {
                mask.s6_addr[full_bytes] = (uint8_t)(UINT8_MAX << (8 - bits_in_partial));
            } else {
                mask.s6_addr[full_bytes] = 0;
            }
            memset(&mask.s6_addr[full_bytes + 1], 0, 16 - full_bytes - 1);
        }

        /* Apply mask to address */
        for (unsigned int i = 0; i < 16; i++) {
            addr.s6_addr[i] &= mask.s6_addr[i];
        }

        /* Convert back to string */
        if (inet_ntop(AF_INET6, &addr, address->value, ADDRLEN) == NULL) {
            return -1;
        }
    } else {
        return -1;
    }

    return 0;
}
