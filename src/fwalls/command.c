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



#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>


#include "../sshguard_log.h"
#include "../sshguard_fw.h"
/* for ADDRLEN: */
#include "../sshguard_addresskind.h"

#include "command.h"

#define MAX_ADDRESSES_PER_LIST      2500

#define COMMAND_ENVNAME_ADDR        "SSHG_ADDR"
#define COMMAND_ENVNAME_ADDRKIND    "SSHG_ADDRKIND"
#define COMMAND_ENVNAME_SERVICE     "SSHG_SERVICE"

static int run_command(const char *restrict command, const char *restrict addr, int addrkind, int service);


int fw_init() {
    return (run_command(COMMAND_INIT, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_fin() {
    return (run_command(COMMAND_FIN, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_block(const char *restrict addr, int addrkind, int service) {
    return (run_command(COMMAND_BLOCK, addr, addrkind, service) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_block_list(const char *restrict addresses[], int addrkind, const int service_codes[]) {
    /* block each address individually */
    int i;

    assert(addresses != NULL);
    assert(service_codes != NULL);

    if (addresses[0] == NULL) return FWALL_OK;

#ifdef COMMAND_BLOCK_LIST
    char address_list[MAX_ADDRESSES_PER_LIST * ADDRLEN];
    address_list[0] = '\0';
    strcpy(address_list, addresses[0]);
    size_t first_free_char = strlen(address_list);
    int j;
    for (i = 1; addresses[i] != NULL; ++i) {
        /* call list-blocking command passing SSHG_ADDRLIST env var as "addr1,addr2,...,addrN" */
        address_list[first_free_char] = ',';
        for (j = 0; addresses[i][j] != '\0'; ++j) {
            address_list[++first_free_char] = addresses[i][j];
        }
        ++first_free_char;

        if (first_free_char >= sizeof(address_list)) {
            sshguard_log(LOG_CRIT, "Wanted to bulk-block %d addresses, but my buffer can't take this many.", i);
            return FWALL_ERR;
        }
    }
    address_list[first_free_char] = '\0';

    /* FIXME: we are blocking all addresses as they were to the same service */
    return run_command(COMMAND_BLOCK_LIST, address_list, addrkind, service_codes[0]);

#else
    int err = FWALL_OK;
    for (i = 0; addresses[i] != NULL; i++) {
        /* repeatedly call single-blocking command for each address */
        if (fw_block(addresses[i], addrkind, service_codes[i]) != FWALL_OK)
            err = FWALL_ERR;
    }

    if (err == FWALL_OK)
        sshguard_log(LOG_INFO, "Blocked %d addresses without errors.", i);
    else
        sshguard_log(LOG_INFO, "Some errors while trying to block %d addresses.", i);

    return err;
#endif
}

int fw_release(const char *restrict addr, int addrkind, int service) {
    return (run_command(COMMAND_RELEASE, addr, addrkind, service) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_flush(void) {
    return (run_command(COMMAND_FLUSH, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

    
static int run_command(const char *restrict command, const char *restrict addr, int addrkind, int service) {
    int ret;
    char *addrks, *servs;


    /* sanity check */
    if (command == NULL || strlen(command) == 0) return 0;

    if (addr != NULL) {
        assert(addrkind == ADDRKIND_IPv4 || addrkind == ADDRKIND_IPv6);

        /* export information to the environment */
        addrks = malloc(5);
        servs = malloc(5);

        snprintf(addrks, 5, "%d", addrkind);
        snprintf(servs, 5, "%d", service);

        setenv(COMMAND_ENVNAME_ADDR, addr, 1);
        setenv(COMMAND_ENVNAME_ADDRKIND, addrks, 1);
        setenv(COMMAND_ENVNAME_SERVICE, servs, 1);

        sshguard_log(LOG_DEBUG, "Setting environment: " COMMAND_ENVNAME_ADDR "=%s;" COMMAND_ENVNAME_ADDRKIND "=%s;" COMMAND_ENVNAME_SERVICE "=%s.", addr, addrks, servs);

        ret = system(command);

        /* cleanup the environment */
        unsetenv(COMMAND_ENVNAME_ADDR);
        unsetenv(COMMAND_ENVNAME_ADDRKIND);
        unsetenv(COMMAND_ENVNAME_SERVICE);
    } else {
        ret = system(command);
    }
    
    ret = WEXITSTATUS(ret);

    sshguard_log(LOG_DEBUG, "Run command \"%s\": exited %d.", command, ret);

    return ret;
}

