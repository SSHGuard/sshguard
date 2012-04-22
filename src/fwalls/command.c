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

/* names of environment variables to pass to external commands */
#define COMMAND_ENVNAME_ACTION      "SSHG_ACTION"
#define COMMAND_ENVNAME_PID         "SSHG_PID"
#define COMMAND_ENVNAME_FWCMD       "SSHG_FWCMD"
#define COMMAND_ENVNAME_ADDR        "SSHG_ADDR"
#define COMMAND_ENVNAME_ADDRKIND    "SSHG_ADDRKIND"
#define COMMAND_ENVNAME_SERVICE     "SSHG_SERVICE"

/* names of actions to pass to external commands */
#define ACTION_NAME_INIT            "init"
#define ACTION_NAME_FIN             "fin"
#define ACTION_NAME_BLOCK           "block"
#define ACTION_NAME_BLOCK_LIST      "block_list"
#define ACTION_NAME_RELEASE         "release"
#define ACTION_NAME_FLUSH           "flush"


/*
 * If getenv("SSHGUARD_EVENT_EXECUTE") is available, this takes it as a command
 * string to execute on every event, before the actual backend command is run.
 *
 * This works trigger-like: if extra_command exits successfully, the actual
 * backend command is executed after it. If extra_command exits with failure,
 * the actual backend command is skipped.
 *
 * The extra command program is passed data through the following environment
 * variables:
 *
 * SSHG_ACTION      --  the name of the action being run
 * SSHG_ADDR        --  address, or CSV list of addresses to operate
 * SSHG_ADDRKIND    --  '4' or '6', for type of addresses in $SSHG_ADDR
 * SSHG_SERVICE     --  code of service target of the event, see sshguard_services.h
 */
const char *extra_command;

/* Prepare the environment variables to execute a command. */
static void prepare_cmd_environment(const char *restrict action_name, const char *restrict command, const char *restrict addr, int addrkind, int service);
/* Clean up the environment variables set to execute a command. */
static void clear_cmd_environment();

/* Run a command for a given event. Takes care of running extra_command before, if any is set. */
static int run_command(const char *action_name, const char *restrict command, const char *restrict addr, int addrkind, int service);


int fw_init() {
    extra_command = getenv("SSHGUARD_EVENT_EXECUTE");
    return (run_command(ACTION_NAME_INIT, COMMAND_INIT, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_fin() {
    int ret;

    ret = run_command(ACTION_NAME_FIN, COMMAND_FIN, NULL, 0, 0);

    clear_cmd_environment();

    extra_command = NULL;

    return (ret == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_block(const char *restrict addr, int addrkind, int service) {
    return (run_command(ACTION_NAME_BLOCK, COMMAND_BLOCK, addr, addrkind, service) == 0 ? FWALL_OK : FWALL_ERR);
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
    return run_command(ACTION_NAME_BLOCK_LIST, COMMAND_BLOCK_LIST, address_list, addrkind, service_codes[0]);

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
    return (run_command(ACTION_NAME_RELEASE, COMMAND_RELEASE, addr, addrkind, service) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_flush(void) {
    return (run_command(ACTION_NAME_FLUSH, COMMAND_FLUSH, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

static void prepare_cmd_environment(const char *restrict action_name, const char *restrict command, const char *restrict addr, int addrkind, int service) {
    char tmpstr[50] = "";

    /* env vars are overwritten at each execution, and ultimately cleaned up at firewall finalization time */

    /* action name */
    setenv(COMMAND_ENVNAME_ACTION, action_name, 1);

    /* PID of sshguard / parent */
    snprintf(tmpstr, sizeof(tmpstr), "%d", getpid());
    setenv(COMMAND_ENVNAME_PID, tmpstr, 1);

    /* firewall command to execute */
    setenv(COMMAND_ENVNAME_FWCMD, command, 1);

    /* any block-specific information? */
    if (addr == NULL) {
        sshguard_log(LOG_DEBUG, "Set environment: " COMMAND_ENVNAME_ACTION
                "=%s;" COMMAND_ENVNAME_PID "=%s", action_name,
                getenv(COMMAND_ENVNAME_PID));
    } else {
        assert(addrkind == ADDRKIND_IPv4 || addrkind == ADDRKIND_IPv6);
        /* addresses */
        setenv(COMMAND_ENVNAME_ADDR, addr, 1);
        /* address kind */
        snprintf(tmpstr, sizeof(tmpstr), "%d", addrkind);
        setenv(COMMAND_ENVNAME_ADDRKIND, tmpstr, 1);
        /* service */
        snprintf(tmpstr, sizeof(tmpstr), "%d", service);
        setenv(COMMAND_ENVNAME_SERVICE, tmpstr, 1);

        sshguard_log(LOG_DEBUG, "Set environment: " COMMAND_ENVNAME_ACTION "=%s;"
                COMMAND_ENVNAME_PID "=%s;" COMMAND_ENVNAME_ADDR "=%s;"
                COMMAND_ENVNAME_ADDRKIND "=%s;" COMMAND_ENVNAME_SERVICE "=%s.",
                action_name,
                getenv(COMMAND_ENVNAME_PID), addr,
                getenv(COMMAND_ENVNAME_ADDRKIND), getenv(COMMAND_ENVNAME_SERVICE));
    }
}

static void clear_cmd_environment() {
    /* clean up environment variables for external-commands */
    unsetenv(COMMAND_ENVNAME_ACTION);
    unsetenv(COMMAND_ENVNAME_PID);
    unsetenv(COMMAND_ENVNAME_FWCMD);
    unsetenv(COMMAND_ENVNAME_ADDR);
    unsetenv(COMMAND_ENVNAME_ADDRKIND);
    unsetenv(COMMAND_ENVNAME_SERVICE);

}

static int run_command(const char *action_name, const char *restrict command, const char *restrict addr, int addrkind, int service) {
    int ret;

    /* prepare environment */
    prepare_cmd_environment(action_name, command, addr, addrkind, service);

    if (extra_command == NULL) {
        /* run backend command directly */
        /* sanity check */
        if (command == NULL || strlen(command) == 0) return 0;
        ret = system(command);
    } else {
        /* extra command specified; run this in place of backend command */
        ret = system(extra_command);
    }
    
    ret = WEXITSTATUS(ret);
    sshguard_log(LOG_DEBUG, "Run command \"%s\": exited %d.", command, ret);

    clear_cmd_environment();

    return ret;
}

