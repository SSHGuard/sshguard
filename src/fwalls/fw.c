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

static FILE *fw_pipe;

static void fw_sigpipe() {
    sshguard_log(LOG_CRIT, "fw: broken pipe");
    exit(EXIT_FAILURE);
}

int fw_init() {
    extra_command = getenv("SSHGUARD_EVENT_EXECUTE");
    signal(SIGPIPE, fw_sigpipe);
    fw_pipe = popen("exec " PREFIX "/libexec/sshg-fw", "w");
    return fw_pipe == NULL ? FWALL_ERR : FWALL_OK;
}

int fw_fin() {
    extra_command = NULL;
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

static void prepare_cmd_environment(const char *restrict action_name, const char *restrict command, const char *restrict addr, int addrkind, int service) {
    char tmpstr[50] = "";

    /* env vars are overwritten at each execution, and ultimately cleaned up at firewall finalization time */

    /* action name */
    setenv(COMMAND_ENVNAME_ACTION, action_name, 1);

    /* PID of sshguard / parent */
    snprintf(tmpstr, sizeof(tmpstr), "%d", getpid());
    setenv(COMMAND_ENVNAME_PID, tmpstr, 1);

    /* firewall command to execute */
    if (command != NULL)
        setenv(COMMAND_ENVNAME_FWCMD, command, 1);
    else
        setenv(COMMAND_ENVNAME_FWCMD, "true", 1);

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

static int run_hook(const char *action_name, const char *restrict command, const char *restrict addr, int addrkind, int service) {
    int ret;

    /* prepare environment */
    prepare_cmd_environment(action_name, command, addr, addrkind, service);

    ret = system(extra_command);
    ret = WEXITSTATUS(ret);
    sshguard_log(LOG_DEBUG, "Run command \"%s\": exited %d.", extra_command, ret);

    clear_cmd_environment();

    return ret;
}

