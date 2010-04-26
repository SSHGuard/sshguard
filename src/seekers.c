#include <string.h>
#include <assert.h>


#include "sshguard_attack.h"
#include "seekers.h"

int seeker_addr(const void *el, const void *key) {
    const sshg_address_t *adr = (const sshg_address_t *)key;
    const attacker_t *atk = (const attacker_t *)el;

    assert(atk != NULL && adr != NULL);
    
    if (atk->attack.address.kind != adr->kind) return 0;
    return (strcmp(atk->attack.address.value, adr->value) == 0);
}

