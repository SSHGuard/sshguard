#include <assert.h>
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

#define IPFWMOD_ADDRESS_BULK_REPRESENTATIVE     "FF:FF:FF:FF:FF:FF:FF:FF"

#define MAXIPFWCMDLEN           90

#ifndef IPFW_RULERANGE_MIN
#define IPFW_RULERANGE_MIN      55000
#endif

#ifndef IPFW_RULERANGE_MAX
#define IPFW_RULERANGE_MAX      55050
#endif

typedef uint16_t ipfw_rulenumber_t;

struct addr_ruleno_s {
    char addr[ADDRLEN];
    int addrkind;
    ipfw_rulenumber_t ruleno;
};

static list_t addrrulenumbers;
static char command[MAXIPFWCMDLEN], args[MAXIPFWCMDLEN];

/* generate an IPFW rule ID for inserting a rule */
static ipfw_rulenumber_t ipfwmod_getrulenumber(void);
/* execute an IPFW command */
static int ipfwmod_runcommand(char *command, char *args);
/* build an IPFW rule for blocking a list of addresses, all of the given kind */
static int ipfwmod_buildblockcommand(ipfw_rulenumber_t ruleno, const char *restrict addresses[], int addrkind, char *restrict command, char *restrict args);

static size_t ipfw_rule_meter(const void *el) { return sizeof(struct addr_ruleno_s); }
static int ipfw_rule_comparator(const void *a, const void *b) {
    struct addr_ruleno_s *A = (struct addr_ruleno_s *)a;
    struct addr_ruleno_s *B = (struct addr_ruleno_s *)b;
    return !((strcmp(A->addr, B->addr) == 0) && (A->addrkind == B->addrkind));
}

int fw_init() {
    srand(time(NULL));
    list_init(&addrrulenumbers);
    list_attributes_copy(& addrrulenumbers, ipfw_rule_meter, 1);
    list_attributes_comparator(& addrrulenumbers, ipfw_rule_comparator);
    return FWALL_OK;
}

int fw_fin() {
    list_destroy(&addrrulenumbers);
    return FWALL_OK;
}

int fw_block(const char *restrict addr, int addrkind, int service) {
    ipfw_rulenumber_t ruleno;
    int ret;
    const char *restrict addresses[2];
    struct addr_ruleno_s addendum;

    /* get a rule number */
    ruleno = ipfwmod_getrulenumber();
    addresses[0] = addr;
    addresses[1] = NULL;
    if (ipfwmod_buildblockcommand(ruleno, addresses, addrkind, command, args) != FWALL_OK)
        return FWALL_ERR;

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

/* add all addresses in one single rule:
 *
 *   ipfw add 1234 drop ipv4 from 1.2.3.4,10.11.12.13,123.234.213.112 to any
 */
int fw_block_list(const char *restrict addresses[], int addrkind, const int service_codes[]) {
    ipfw_rulenumber_t ruleno;
    struct addr_ruleno_s addendum;
    int ret;

    
    assert(addresses != NULL);
    assert(service_codes != NULL);

    ruleno = ipfwmod_getrulenumber();
    /* insert rules under this rule number (in chunks of max_addresses_per_rule) */
    if (ipfwmod_buildblockcommand(ruleno, addresses, addrkind, command, args) != FWALL_OK)
        return FWALL_ERR;

    /* run command */
    ret = ipfwmod_runcommand(command, args);
    if (ret != 0) {
        sshguard_log(LOG_ERR, "Command \"%s %s\" exited %d", command, args, ret);
        return FWALL_ERR;
    }
    
    sshguard_log(LOG_DEBUG, "Command exited %d.", ret);

    /* insert a placeholder for the bulk */
    strcpy(addendum.addr, IPFWMOD_ADDRESS_BULK_REPRESENTATIVE);
    addendum.ruleno = ruleno;
    addendum.addrkind = addrkind;
    list_append(& addrrulenumbers, & addendum);

    return FWALL_OK;
}


int fw_release(const char *restrict addr, int addrkind, int service) {
    struct addr_ruleno_s data;
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
    int ret = 0;

    if (list_empty(& addrrulenumbers)) return FWALL_OK;

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

static ipfw_rulenumber_t ipfwmod_getrulenumber(void) {
    /* choose a random number to assign to IPFW rule */
    return (rand() % (IPFW_RULERANGE_MAX - IPFW_RULERANGE_MIN)) + IPFW_RULERANGE_MIN;
}

static int ipfwmod_runcommand(char *command, char *args) {
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

static int ipfwmod_buildblockcommand(ipfw_rulenumber_t ruleno, const char *restrict addresses[], int addrkind, char *restrict command, char *restrict args) {
    int i;

    assert(addresses != NULL);
    assert(addresses[0] != NULL     /* there is at least one address to block */);
    assert(command != NULL);
    assert(args != NULL);

    /*
     * command looks like
     *      /full/path/to/ipfw
     *          -or-
     *      /full/path/to/ip6fw     (on systems that require ip6fw to block IPv6)
     *
     * args is the rule arguments; it looks like:
     *      add <rulenum> drop <ip|ipv6> from addr1,addr2...,addrN to me
     */
    switch (addrkind) {
        case ADDRKIND_IPv4:
            /* use ipfw */
            sprintf(command, IPFW_PATH "/ipfw");
            sprintf(args, "add %u drop ip", ruleno);
            break;

        case ADDRKIND_IPv6:
#ifdef FWALL_HAS_IP6FW
            /* use ip6fw if found */
	    	sprintf(command, IPFW_PATH "/ip6fw");
#else
            /* use ipfw, assume it supports IPv6 rules as well */
	    	sprintf(command, IPFW_PATH "/ipfw");
#endif
            sprintf(args, "add %u drop ipv6", ruleno);
            break;

        default:
            return FWALL_UNSUPP;
    }

    /* add the rest of the rule */
    sprintf(args, " from %s", addresses[0]);
    for (i = 1; addresses[i] != NULL; ++i) {
        sprintf(args, ",%s", addresses[i]);
    }
    sprintf(args, " to me");

    return FWALL_OK;
}


