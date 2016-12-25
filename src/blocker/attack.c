#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "attack.h"

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
