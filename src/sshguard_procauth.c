/*
 * Copyright (c) 2007,2008 Mij <mij@sshguard.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <regex.h>
#include <simclist.h>

#include "sshguard_log.h"
#include "sshguard_procauth.h"

typedef struct {
    int service_code;
    char *filename;
    pid_t current_pid;
} procpid;

size_t procpid_meter(const void *el) {
    return sizeof(procpid);
}

/* list of services whose serving process ID has to assured authentic */
list_t proclist;

static pid_t procauth_getprocpid(char *filename);
static int procauth_ischildof(pid_t child, pid_t parent);



int procauth_init() {
    /* assume random number generator already seeded */
    list_init(&proclist);
    list_attributes_copy(&proclist, procpid_meter, 1);

    return 0;
}

int procauth_fin() {
    procpid *pp;

    /* free filenames */
    list_iterator_start(&proclist);
    while (list_iterator_hasnext(&proclist)) {
        pp = (procpid *)list_iterator_next(&proclist);
        free(pp->filename);
    }
    list_iterator_stop(&proclist);

    /* destroy the list itself */
    list_destroy(&proclist);
    return 0;
}

int procauth_addprocess(char *conf) {
    procpid pp;
    int srvcode;
    char pidfilename[FILENAME_MAX];

    /* ensure the filename length is within system limit */ 
    if (memchr(conf, '\0', FILENAME_MAX) == NULL)
	return -1;

    /* conf format:     service_code:pid_filename   */
    if (sscanf(conf, "%d:%s", &srvcode, pidfilename) != 2)
        return -1;

    pp.service_code = srvcode;
    pp.filename = (char *)malloc(strlen(pidfilename) + 1);
    strcpy(pp.filename, pidfilename);
    /* get current pid */
    pp.current_pid = procauth_getprocpid(pidfilename);

    /* append process block to the list */
    list_append(&proclist, &pp);
    sshguard_log(LOG_INFO, "authenticating service %d with process ID from %s", pp.service_code, pp.filename);

    return 0;
}

int procauth_refreshpids() {
    procpid *pp;
    pid_t newpid;
    int changed = 0;

    /* update each process in list with the current pid */
    list_iterator_start(&proclist);
    while (list_iterator_hasnext(&proclist)) {
        pp = (procpid *)list_iterator_next(&proclist);
        newpid  = procauth_getprocpid(pp->filename);
        if (newpid != pp->current_pid) changed++;
        pp->current_pid = newpid;
    }
    list_iterator_stop(&proclist);
    sshguard_log(LOG_DEBUG,"refreshing the list of pids from pidfiles... %d pids changed", changed);

    return changed;
}

int procauth_isauthoritative(int service_code, pid_t pid) {
    procpid *pp;

    list_iterator_start(&proclist);
    while (list_iterator_hasnext(&proclist)) {
        pp = (procpid *)list_iterator_next(&proclist);
        if (pp->service_code == service_code) {
            /* wanted service found, compare pids... */
            list_iterator_stop(&proclist);
            if (pp->current_pid == pid) /* authoritative */
                return 1;
            else {
                pp->current_pid = procauth_getprocpid(pp->filename);
                if (pp->current_pid == -1) {        /* error accessing pidfile */
                    return 0;
                } else {
                    if (pp->current_pid != pid) {
                        /* check if this is a child of the parent pid */
                        return procauth_ischildof(pid, pp->current_pid);
                    }
                    /* pid correctly updated and matching */
                    return 1;
                }
            }
        }
    }
    list_iterator_stop(&proclist);

    /* service_code was unknown */
    return 0;
}

static pid_t procauth_getprocpid(char *filename) {
    FILE *pf;
    pid_t pid;

    pf = fopen(filename, "r");
    if (pf == NULL) {
        sshguard_log(LOG_NOTICE, "unable to open pidfile '%s': %s.", filename, strerror(errno));
        return -1;
    }

    if (fscanf(pf, "%d", &pid) != 1) {
        sshguard_log(LOG_INFO, "pid file '%s' malformed. Expecting one pid.", filename);
        return -1;
    }
    fclose(pf);

    return pid;
}

static int procauth_ischildof(pid_t child, pid_t parent) {
    char mystring[100];
    int ischild;
    int ret;
    int ps2me[2];
    regex_t pschild_re;
    pid_t pid;
    FILE *psout;


    sprintf(mystring, "^%d[[:space:]]+%d[[:space:]]*$", child, parent);
    regcomp(& pschild_re, mystring, REG_EXTENDED);
    sshguard_log(LOG_DEBUG, "Testing if %d is child of %d.", child, parent);

    pipe(ps2me);

    /* execute ps command, pipe result to us */
    if ((pid = fork()) == 0) {
        /* child */
        close(0);
        dup2(ps2me[1], 1);

        sshguard_log(LOG_ERR, "Running 'ps axo pid,ppid'.");
        execlp("ps", "ps", "axo", "pid,ppid", NULL);

        sshguard_log(LOG_ERR, "Unable to run 'ps axo pid,ppid': %s.", strerror(errno));
        exit(-1);
    }

    /* father */
    close(ps2me[1]);

    /* read lines returned the ps' output, and match pschild_re */
    psout = fdopen(ps2me[0], "r");
    if (psout == NULL) return 0;

    ischild = 0;
    while (fgets(mystring, sizeof(mystring), psout) != NULL) {
        if (regexec(& pschild_re, mystring, 0, NULL, 0) == 0) {
            ischild = 1;
            break;
        }
    }
    regfree(& pschild_re);

    waitpid(pid, & ret, 0);
    if (! WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
        sshguard_log(LOG_ERR, "ps command failed to run.");
        return 0;
    }
    
    sshguard_log(LOG_INFO, "Process %d %s child of %d.", child, (ischild ? "is" : "is not"), parent);
    /* return YES or NO answer */
    if (ischild)
        return 1;

    return -1;
}

