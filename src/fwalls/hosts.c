/*
 * Copyright (c) 2007,2008,2009 Mij <mij@sshguard.net>
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
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <simclist.h>

#include "../config.h"
#include "../sshguard_log.h"
#include "../sshguard_fw.h"

#ifndef HOSTSFILE_PATH
#   define HOSTSFILE_PATH     "/etc/hosts.allow"
#endif
#define HOSTS_MAXCMDLEN       1024

/* hosts_access limits line length. How many addresses per line to use? */
#define HOSTS_ADDRS_PER_LINE    8

#define HOSTS_SSHGUARD_PREFIX "###sshguard###\n"
#define HOSTS_SSHGUARD_SUFFIX "###sshguard###\n"

typedef struct {
    char addr[ADDRLEN];
    int addrkind;
    int service;
} addr_service_t;

int hosts_updatelist();
int hosts_clearsshguardblocks(void);

list_t hosts_blockedaddrs;
FILE *hosts_file;

/* buffer to hold the name of temporary configuration files. Set once, in fw_init() */
#define MAX_TEMPFILE_NAMELEN        60
static char tempflname[MAX_TEMPFILE_NAMELEN] = "";

size_t addr_service_meter(const void *el) { return sizeof(addr_service_t); }
int addr_service_comparator(const void *a, const void *b) {
    addr_service_t *A = (addr_service_t *)a;
    addr_service_t *B = (addr_service_t *)b;
    return !((strcmp(A->addr, B->addr) == 0) && (A->addrkind == B->addrkind) && (A->service == B->service));
}

static FILE *make_temporary_conffile(void) {
    return  fopen(tempflname, "a+");
}

static int install_temporary_conffile() {
    if (rename(tempflname, HOSTSFILE_PATH) != 0) {
        sshguard_log(LOG_CRIT, "OUCHH! Could not rename temp file '%s' to '%s' (%s).", tempflname, HOSTSFILE_PATH, strerror(errno));
        return FWALL_ERR;
    }

    return FWALL_OK;
}

int fw_init() {
    char buf[HOSTS_MAXCMDLEN];
    FILE *tmp, *deny;

    /* set the filename of the temporary configuration file */
    if (snprintf(tempflname, MAX_TEMPFILE_NAMELEN, "%s-sshguard.%u", HOSTSFILE_PATH, getpid()) >= MAX_TEMPFILE_NAMELEN) {
        sshguard_log(LOG_ERR, "'tempflname' buffer too small to hold '%s-sshguard.%u!'", HOSTSFILE_PATH, getpid());
        return FWALL_ERR;
    }

    hosts_clearsshguardblocks();

    /* place sshguard block delimiters (header/footer) into HOSTSFILE_PATH */
    deny = fopen(HOSTSFILE_PATH, "r+");
    if (deny == NULL) {
        sshguard_log(LOG_ERR, "Could not initialize " HOSTSFILE_PATH " for use by sshguard: %s", strerror(errno));
        return FWALL_ERR;
    }

    tmp = make_temporary_conffile();
    if (tmp == NULL) {
        sshguard_log(LOG_ERR, "Could not create temporary file %s!", tempflname);
        fclose(deny);
        return FWALL_ERR;
    }
    fprintf(tmp, "%s%s", HOSTS_SSHGUARD_PREFIX, HOSTS_SSHGUARD_SUFFIX);

    /* copy the original content of HOSTSFILE_PATH into tmp */
    while (fgets(buf, HOSTS_MAXCMDLEN, deny) != NULL) {
        fprintf(tmp, "%s", buf);
    }
    
    fclose(tmp);
    fclose(deny);

    /* install temporary conf file into main file */
    if (install_temporary_conffile() != FWALL_OK)
        return FWALL_ERR;

    list_init(&hosts_blockedaddrs);
    list_attributes_copy(&hosts_blockedaddrs, addr_service_meter, 1);
    list_attributes_comparator(&hosts_blockedaddrs, addr_service_comparator);

    return FWALL_OK;
}

int fw_fin() {
    hosts_clearsshguardblocks();
    list_destroy(&hosts_blockedaddrs);
    return FWALL_OK;
}

int fw_block(const char *restrict addr, int addrkind, int service) {
    addr_service_t ads;

    strcpy(ads.addr, addr);
    ads.service = service;
    ads.addrkind = addrkind;
    list_append(&hosts_blockedaddrs, &ads);

    return hosts_updatelist();
}

int fw_block_list(const char *restrict addresses[], int addrkind, const int service_codes[]) {
    int cnt;
    addr_service_t ads;

    for (cnt = 0; addresses[cnt] != NULL; ++cnt) {
        strcpy(ads.addr, addresses[cnt]);
        ads.addrkind = addrkind;
        ads.service = service_codes[cnt];

        list_append(& hosts_blockedaddrs, & ads);
    }
    
    return hosts_updatelist();
}

int fw_release(const char *restrict addr, int addrkind, int services) {
    int pos;

    if ((pos = list_locate(&hosts_blockedaddrs, addr)) < 0) {
        return FWALL_ERR;
    }

    list_delete_at(&hosts_blockedaddrs, pos);
    return hosts_updatelist();
}

int fw_flush(void) {
    list_clear(&hosts_blockedaddrs);
    return hosts_updatelist();
}

int hosts_updatelist() {
    char buf[HOSTS_MAXCMDLEN];
    FILE *tmp, *deny;

    /* open hosts.allow file */
    deny = fopen(HOSTSFILE_PATH, "r+");
    if (deny == NULL) {
        sshguard_log(LOG_ERR, "Could not open hosts.allow file %s: %s", HOSTSFILE_PATH, strerror(errno));
        return FWALL_ERR;
    }

    /* create/open a temporary file */
    tmp = make_temporary_conffile();
    if (tmp == NULL) {
        sshguard_log(LOG_ERR, "Could not create temporary file %s!", tempflname);
        fclose(deny);
        return FWALL_ERR;
    }

    /* copy everything until sshguard prefix line */
    while (fgets(buf, HOSTS_MAXCMDLEN, deny) != NULL) {
        fprintf(tmp, "%s", buf);
        if (strcmp(buf, HOSTS_SSHGUARD_PREFIX) == 0) break;
    }

    /* sanity check */
    if (strcmp(buf, HOSTS_SSHGUARD_PREFIX) != 0) {
        sshguard_log(LOG_ERR, "hosts.allow file did not contain sshguard rules block.");
        fclose(deny);
        fclose(tmp);
        unlink(tempflname);
        return FWALL_ERR;
    }

    if (list_size(& hosts_blockedaddrs) > 0) {
        unsigned int cnt;
        addr_service_t *curr;

        fprintf(tmp, "ALL :");
        for (cnt = 0; cnt < (int)list_size(&hosts_blockedaddrs); cnt++) {
            curr = (addr_service_t *)list_get_at(&hosts_blockedaddrs, cnt);

            /* block lines differ depending on IP Version */
            switch (curr->addrkind) {
                case ADDRKIND_IPv4:
                    fprintf(tmp, " %s", curr->addr);
                    break;

                case ADDRKIND_IPv6:
                    fprintf(tmp, " [%s]", curr->addr);
                    break;
            }

            if (((cnt+1) % HOSTS_ADDRS_PER_LINE) == 0) {
                /* switch to new line */
                fprintf(tmp, " : DENY\nALL : ");
            }
        }
        fprintf(tmp, " : DENY\n");
    }    
    fprintf(tmp, HOSTS_SSHGUARD_SUFFIX);

    /* getting to the end of the original block */
    while (fgets(buf, HOSTS_MAXCMDLEN, deny)) {
        if (strcmp(buf, HOSTS_SSHGUARD_SUFFIX) == 0) break;
    }

    /* sanity check */
    if (strcmp(buf, HOSTS_SSHGUARD_SUFFIX) != 0) {
        sshguard_log(LOG_ERR, "hosts.allow file's sshguard rules block was malformed.");
        fclose(deny);
        fclose(tmp);
        unlink(tempflname);
        return FWALL_ERR;
    }

    /* copy the rest of the original file */
    while (fgets(buf, HOSTS_MAXCMDLEN, deny)) {
        fprintf(tmp, "%s", buf);
    }

    fclose(tmp);
    fclose(deny);

    /* move tmp over to deny */
    if (install_temporary_conffile() != FWALL_OK) {
        sshguard_log(LOG_CRIT, "OUCHH! Could not rename temp file '%s' to '%s' (%s).", tempflname, HOSTSFILE_PATH, strerror(errno));
        return FWALL_ERR;
    }

#if 0
    fseek(tmp, 0, SEEK_SET);
    fseek(deny, 0, SEEK_SET);
    while(fgets(buf, HOSTS_MAXCMDLEN, tmp) != NULL) {
        fprintf(deny, "%s", buf);
    }
    ftruncate(fileno(deny), ftell(tmp));
    fclose(tmp);
    fclose(deny);
    close(fd);
    unlink(tempflname);
#endif

    return FWALL_OK;
}

int hosts_clearsshguardblocks(void) {
    char buf[HOSTS_MAXCMDLEN];
    int docopy;
    FILE *tmp, *deny;

    /* open deny file */
    deny = fopen(HOSTSFILE_PATH, "r+");
    if (deny == NULL) {
        sshguard_log(LOG_ERR, "unable to open hosts file %s: %s", HOSTSFILE_PATH, strerror(errno));
        return FWALL_ERR;
    }

    /* create/open a temporary file */
    tmp = make_temporary_conffile();
    if (tmp == NULL) {
        sshguard_log(LOG_ERR, "Could not create temporary file %s!", tempflname);
        fclose(deny);
        return FWALL_ERR;
    }

    /* save to tmp only those parts that are not sshguard blocks */
    docopy = 1;
    while (fgets(buf, HOSTS_MAXCMDLEN, deny) != NULL) {
        switch (docopy) {
            case 1:
                if (strcmp(buf, HOSTS_SSHGUARD_PREFIX) == 0) {
                    docopy = 0;
                } else {
                    fprintf(tmp, "%s", buf);
                }
                break;
            case 0:
                if (strcmp(buf, HOSTS_SSHGUARD_SUFFIX) == 0) {
                    docopy = 1;
                }
                break;
        }
    }

    fclose(tmp);
    fclose(deny);

    /* move tmp over to deny */
    if (install_temporary_conffile() != FWALL_OK) {
        sshguard_log(LOG_CRIT, "OUCHH! Could not rename temp file '%s' to '%s' (%s).", tempflname, HOSTSFILE_PATH, strerror(errno));
        return FWALL_ERR;
    }

    return FWALL_OK;
}
