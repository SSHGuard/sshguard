#include <errno.h>
#include <time.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <simclist.h>
#include <sys/types.h>
#include <unistd.h>

#include "../config.h"
#include "../sshguard_log.h"
#include "../sshguard_fw.h"

#define MAXIPFWCMDLEN           90

#ifndef IPFW_RULERANGE_MIN
#define IPFW_RULERANGE_MIN      55000
#endif

#ifndef IPFW_RULERANGE_MAX
#define IPFW_RULERANGE_MAX      55050
#endif

struct addr_ruleno_s {
    char addr[ADDRLEN];
    int addrkind;
    unsigned int ruleno;
};

list_t addrrulenumbers;


int ipfwmod_runcommand(char *command, char *args);
void ipfwmod_logsystemretval(char *command, int returnval);

size_t ipfw_rule_meter(const void *el) { return sizeof(struct addr_ruleno_s); }
int ipfw_rule_comparator(const void *a, const void *b) {
    struct addr_ruleno_s *A = (struct addr_ruleno_s *)a;
    struct addr_ruleno_s *B = (struct addr_ruleno_s *)b;
    return !((strcmp(A->addr, B->addr) == 0) && (A->addrkind == B->addrkind));
}

int fw_init() {
    srandom(time(NULL));
    list_init(&addrrulenumbers);
    list_attributes_copy(& addrrulenumbers, ipfw_rule_meter, 1);
    list_attributes_comparator(& addrrulenumbers, ipfw_rule_comparator);
    return FWALL_OK;
}

int fw_fin() {
    list_destroy(&addrrulenumbers);
    return FWALL_OK;
}

int fw_block(char *addr, int addrkind, int service) {
    unsigned int ruleno;
    int ret;
    char command[MAXIPFWCMDLEN], args[MAXIPFWCMDLEN];
    struct addr_ruleno_s addendum;

    /* choose a random number to assign to IPFW rule */
    ruleno = (random() % (IPFW_RULERANGE_MAX - IPFW_RULERANGE_MIN)) + IPFW_RULERANGE_MIN;
    switch (addrkind) {
        case ADDRKIND_IPv4:
            /* use ipfw */
            sprintf(command, IPFW_PATH "/ipfw");
            break;
        case ADDRKIND_IPv6:
#ifdef FWALL_HAS_IP6FW
            /* use ip6fw if found */
	    	sprintf(command, IPFW_PATH "/ip6fw");
#else
            /* use ipfw, assume it supports IPv6 rules as well */
	    	sprintf(command, IPFW_PATH "/ipfw");
#endif
            break;
        default:
            return FWALL_UNSUPP;
    }
    /* build command arguments */
    sprintf(args, "add %u drop ip from %s to me", ruleno, addr);
            
    /* run command */
    ret = ipfwmod_runcommand(command, args);
    if (ret != 0) {
        sshguard_log(LOG_ERR, "Command \"%s %s\" exited %d", command, args, ret);
        return FWALL_ERR;
    }
    
    sshguard_log(LOG_DEBUG, "Command exited %d.", ret);

    /* success, save rule number */
    strcpy(addendum.addr, addr);
    addendum.ruleno = ruleno;
    addendum.addrkind = addrkind;

    list_append(&addrrulenumbers, &addendum);
    
    return FWALL_OK;
}

int fw_release(char *addr, int addrkind, int service) {
    struct addr_ruleno_s data;
    char args[MAXIPFWCMDLEN], command[MAXIPFWCMDLEN];
    int pos, ret = 0;

    /* retrieve ID of rule blocking "addr" */
    strcpy(data.addr, addr);
    data.addrkind = addrkind;
    if ((pos = list_locate(& addrrulenumbers, &data)) < 0) {
        sshguard_log(LOG_ERR, "could not get back rule ID for address %s", addr);
        return FWALL_ERR;
    }
    data = *(struct addr_ruleno_s *)list_get_at(& addrrulenumbers, pos);

    switch (data.addrkind) {
        case ADDRKIND_IPv4:
            /* use ipfw */
            sprintf(command, IPFW_PATH "/ipfw");
            break;
        case ADDRKIND_IPv6:
#ifdef FWALL_HAS_IP6FW
            /* use ip6fw if found */
	    	sprintf(command, IPFW_PATH "/ip6fw");
#else
            /* use ipfw, assume it supports IPv6 rules as well */
	    	sprintf(command, IPFW_PATH "/ipfw");
#endif
            break;
        default:
            return FWALL_UNSUPP;
    }
    /* build command arguments */
    snprintf(args, MAXIPFWCMDLEN, "delete %u", data.ruleno);

    sshguard_log(LOG_DEBUG, "running: '%s %s'", command, args);

    /* run command */
    ret = ipfwmod_runcommand(command, args);
    if (ret != 0) {
        sshguard_log(LOG_ERR, "Command \"%s %s\" exited %d", command, args, ret);
        return FWALL_ERR;
    }
    
    sshguard_log(LOG_DEBUG, "Command exited %d.", ret);

    list_delete_at(&addrrulenumbers, pos);

    return FWALL_OK;
}

int fw_flush(void) {
    struct addr_ruleno_s *data;
    char command[MAXIPFWCMDLEN], args[MAXIPFWCMDLEN];
    int ret;

    list_iterator_start(&addrrulenumbers);
    while (list_iterator_hasnext(&addrrulenumbers)) {
        data = (struct addr_ruleno_s *)list_iterator_next(& addrrulenumbers);
        switch (data->addrkind) {
            case ADDRKIND_IPv4:
                snprintf(command, MAXIPFWCMDLEN, IPFW_PATH "/ipfw");
                break;
            case ADDRKIND_IPv6:
#ifdef FWALL_HAS_IP6FW
                /* use ip6fw if found */
                sprintf(command, IPFW_PATH "/ip6fw");
#else
                /* use ipfw, assume it supports IPv6 rules as well */
                sprintf(command, IPFW_PATH "/ipfw");
#endif
                break;
        }
        sprintf(args, "delete %u", data->ruleno);
        sshguard_log(LOG_DEBUG, "running: '%s %s'", command, args);
        ret = ipfwmod_runcommand(command, args);
        if (ret != 0) {
            sshguard_log(LOG_ERR, "Command \"%s %s\" exited %d", command, args, ret);
        }
    }

    sshguard_log(LOG_DEBUG, "Command exited %d.", ret);
    
    list_iterator_stop(& addrrulenumbers);
    
    list_clear(&addrrulenumbers);

    return FWALL_OK;
}

int ipfwmod_runcommand(char *command, char *args) {
    char *argsvec[20];
    pid_t pid;
    int i, j, ret;
    char *locargs = malloc(strlen(args)+1);

    sshguard_log(LOG_DEBUG, "Running command: '%s %s'.", command, args);

    argsvec[0] = command;
    strcpy(locargs, args);

    /* tokenize command */
    argsvec[1] = locargs;
    for (j = 2,i = 1; i < (int)strlen(args); i++) {
        if (locargs[i] == ' ') {
            /* jump multiple spaces */
            if (locargs[i+1] == ' ' || locargs[i+1] == '\0') continue;
            locargs[i] = '\0';
            argsvec[j++] = locargs+i+1;
        }
    }
    argsvec[j] = NULL;

    pid = fork();
    if (pid == 0) {
        /* in child; run command */
        execvp(argsvec[0], argsvec);
        sshguard_log(LOG_ERR, "Unable to run command: %s", strerror(errno));
        _Exit(1);
    }
    free(locargs);
    waitpid(pid, &ret, 0);
    ret = WEXITSTATUS(ret);

    return ret;
}

