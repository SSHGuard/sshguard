#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>


#include "../sshguard_log.h"
#include "../sshguard_fw.h"
#include "command.h"

#define COMMAND_ENVNAME_ADDR        "SSHG_ADDR"
#define COMMAND_ENVNAME_ADDRKIND    "SSHG_ADDRKIND"
#define COMMAND_ENVNAME_SERVICE     "SSHG_SERVICE"

static int run_command(char *command, char *addr, int addrkind, int service);


int fw_init() {
    return (run_command(COMMAND_INIT, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_fin() {
    return (run_command(COMMAND_FIN, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_block(char *addr, int addrkind, int service) {
    return (run_command(COMMAND_BLOCK, addr, addrkind, service) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_release(char *addr, int addrkind, int service) {
    return (run_command(COMMAND_RELEASE, addr, addrkind, service) == 0 ? FWALL_OK : FWALL_ERR);
}

int fw_flush(void) {
    return (run_command(COMMAND_FLUSH, NULL, 0, 0) == 0 ? FWALL_OK : FWALL_ERR);
}

    
static int run_command(char *command, char *addr, int addrkind, int service) {
    int ret;
    char *addrks, *servs;

    /* sanity check */
    if (command == NULL || strlen(command) == 0) return 0;

    if (addr != NULL) {
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

