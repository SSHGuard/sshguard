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

static FILE *fw_pipe;

static void fw_sigpipe() {
    sshguard_log(LOG_CRIT, "fw: broken pipe");
    exit(EXIT_FAILURE);
}

int fw_init() {
    signal(SIGPIPE, fw_sigpipe);
    fw_pipe = popen("exec " LIBEXECDIR "/sshg-fw", "w");

    // Wait for sshg-fw to initialize and check if it's still up.
    sleep(1);
    fprintf(fw_pipe, "noop\n");
    fflush(fw_pipe);

    return fw_pipe == NULL ? FWALL_ERR : FWALL_OK;
}

int fw_fin() {
    fprintf(fw_pipe, "\n");
    fflush(fw_pipe);
    return pclose(fw_pipe) == 0 ? FWALL_OK : FWALL_ERR;
}

int fw_block(const attack_t *attack) {
    fprintf(fw_pipe, "block %s %d\n", attack->address.value, attack->address.kind);
    return fflush(fw_pipe) == 0 ? FWALL_OK : FWALL_ERR;
}

int fw_release(const attack_t *attack) {
    fprintf(fw_pipe, "release %s %d\n", attack->address.value, attack->address.kind);
    return fflush(fw_pipe) == 0 ? FWALL_OK : FWALL_ERR;
}

int fw_flush() {
    fprintf(fw_pipe, "flush\n");
    return fflush(fw_pipe) == 0 ? FWALL_OK : FWALL_ERR;
}
