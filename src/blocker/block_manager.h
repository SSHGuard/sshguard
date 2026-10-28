#pragma once

#include <stdbool.h>

#include "attack.h"

#define INFINITE_PARDON 0

unsigned int fw_block_subnet_size(int inet_family);

bool block_store_contains(const sshg_address_t *target);
void block_store_add(const attacker_t *attacker);
void block_manager_start(void);

void blacklist_load_and_block();
