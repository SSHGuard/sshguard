#pragma once

#include <stdbool.h>

#include "attack.h"

unsigned int fw_block_subnet_size(int inet_family);

bool blocklist_contains(attack_t);
void blocklist_add(attacker_t *);
void blocklist_init();

void blacklist_load_and_block();
