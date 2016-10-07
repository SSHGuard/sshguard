/*
 * Copyright (c) 2007,2008,2010 Mij <mij@sshguard.net>
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

#include "config.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fw.h"
#include "parser/address.h"
#include "sshguard_log.h"

static void fw_sigpipe() {
    sshguard_log(LOG_CRIT, "fw: broken pipe");
    exit(EXIT_FAILURE);
}

int fw_init() {
    printf("flushonexit\n");
    fflush(stdout);
    return FWALL_OK;
}

int fw_fin() {
    return FWALL_OK;
}

int fw_block(const attack_t *attack) {
    printf("block %s %d\n", attack->address.value, attack->address.kind);
    fflush(stdout);
    return FWALL_OK;
}

int fw_release(const attack_t *attack) {
    printf("release %s %d\n", attack->address.value, attack->address.kind);
    fflush(stdout);
    return FWALL_OK;
}

int fw_flush() {
    printf("flush\n");
    fflush(stdout);
    return FWALL_OK;
}
