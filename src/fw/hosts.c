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

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fw.h"
#include "simclist.h"

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
    unsigned int subnet;
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
    return !((strcmp(A->addr, B->addr) == 0) && (A->addrkind == B->addrkind) &&
             (A->subnet == B->subnet));
}

static FILE *make_temporary_conffile(void) {
    FILE *f;

    f = fopen(tempflname, "w+");
    if (f == NULL) return NULL;

    /* make sure to secure file permissions (-rw-r--r--) */
    if (chmod(tempflname, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
        /* could not secure perms, return full failure */
        perror("could not chmod");
        fclose(f);
        unlink(tempflname);
        return NULL;
    }

    return f;
}

static int install_temporary_conffile() {
    if (rename(tempflname, HOSTSFILE_PATH) != 0) {
        perror("could not rename temporary file");
        return FWALL_ERR;
    }

    return FWALL_OK;
}

int fw_init() {
    char buf[HOSTS_MAXCMDLEN];
    FILE *tmp, *deny;

    /* set the filename of the temporary configuration file */
    if (snprintf(tempflname, MAX_TEMPFILE_NAMELEN, "%s-sshguard.%u", HOSTSFILE_PATH, getpid()) >= MAX_TEMPFILE_NAMELEN) {
        fprintf(stderr, "'tempflname' buffer too small to hold '%s-sshguard.%u!'", HOSTSFILE_PATH, getpid());
        return FWALL_ERR;
    }

    hosts_clearsshguardblocks();

    /* place sshguard block delimiters (header/footer) into HOSTSFILE_PATH */
    deny = fopen(HOSTSFILE_PATH, "r+");
    if (deny == NULL) {
        perror("could not open hosts.allow");
        return FWALL_ERR;
    }

    tmp = make_temporary_conffile();
    if (tmp == NULL) {
        perror("could not create temporary file");
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

int fw_block(const attack_t *attack, unsigned int subnet) {
    addr_service_t ads;

    strcpy(ads.addr, attack->address.value);
    ads.addrkind = attack->address.kind;
    ads.subnet = subnet;
    list_append(&hosts_blockedaddrs, &ads);

    return hosts_updatelist();
}

int fw_release(const attack_t *attack, unsigned int subnet) {
    int pos;
    addr_service_t ads;

    strcpy(ads.addr, attack->address.value);
    ads.addrkind = attack->address.kind;
    ads.subnet = subnet;

    if ((pos = list_locate(&hosts_blockedaddrs, &ads)) < 0) {
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
        perror("could not open hosts.allow");
        return FWALL_ERR;
    }

    /* create/open a temporary file */
    tmp = make_temporary_conffile();
    if (tmp == NULL) {
        perror("could not create temporary file");
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
        fprintf(stderr, "hosts.allow file did not contain sshguard rules block\n");
        fclose(deny);
        fclose(tmp);
        unlink(tempflname);
        return FWALL_ERR;
    }

    if (list_size(& hosts_blockedaddrs) > 0) {
        addr_service_t *curr;

        fprintf(tmp, "ALL :");
        for (unsigned int cnt = 0; cnt < list_size(&hosts_blockedaddrs); cnt++) {
            curr = (addr_service_t *)list_get_at(&hosts_blockedaddrs, cnt);

            /* block lines differ depending on IP Version */
            switch (curr->addrkind) {
                case ADDRKIND_IPv4:
                    fprintf(tmp, " %s", curr->addr);
                    if (curr->subnet != 32) {
                        struct in_addr mask;
                        char maskbuf[INET_ADDRSTRLEN];
                        mask.s_addr = htonl(curr->subnet == 0 ? 0 :
                                           0xffffffffU << (32 - curr->subnet));
                        inet_ntop(AF_INET, &mask, maskbuf, sizeof(maskbuf));
                        fprintf(tmp, "/%s", maskbuf);
                    }
                    break;

                case ADDRKIND_IPv6:
                    fprintf(tmp, " [%s]", curr->addr);
                    if (curr->subnet != 128) {
                        fprintf(tmp, "/%u", curr->subnet);
                    }
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
        fprintf(stderr, "hosts.allow file's sshguard rules block was malformed\n");
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
        perror("could not rename temporary file");
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
        perror("could not open hosts.allow file");
        return FWALL_ERR;
    }

    /* create/open a temporary file */
    tmp = make_temporary_conffile();
    if (tmp == NULL) {
        perror("could not create temporary file");
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
        perror("could not rename temporary file");
        return FWALL_ERR;
    }

    return FWALL_OK;
}

static bool fill_attack(attack_t *attack, unsigned int *subnet,
                        const char *addr, const char *type, const char *size) {
    unsigned char bytes[16];
    char *end;
    long prefix;
    int family, maxbits;

    if (addr == NULL || type == NULL || size == NULL) {
        return false;
    }
    if (strcmp(type, "4") == 0) {
        family = AF_INET;
        maxbits = 32;
        attack->address.kind = ADDRKIND_IPv4;
    } else if (strcmp(type, "6") == 0) {
        family = AF_INET6;
        maxbits = 128;
        attack->address.kind = ADDRKIND_IPv6;
    } else {
        return false;
    }
    if (*size < '0' || *size > '9') {
        return false;
    }
    errno = 0;
    prefix = strtol(size, &end, 10);
    if (errno != 0 || *end != '\0' || prefix < 0 || prefix > maxbits ||
        inet_pton(family, addr, bytes) != 1) {
        return false;
    }

    /* hosts_access requires the network, not a host within it. */
    for (int bit = (int)prefix; bit < maxbits; bit++) {
        bytes[bit / 8] &= ~(1U << (7 - bit % 8));
    }
    if (inet_ntop(family, bytes, attack->address.value,
                  sizeof(attack->address.value)) == NULL) {
        return false;
    }
    *subnet = (unsigned int)prefix;
    return true;
}

void backend_main(const char *name) {
    if (fw_init() != FWALL_OK) {
        fprintf(stderr, "%s: Could not initialize firewall\n", name);
        exit(69);
    }
    atexit((void (*)(void))fw_fin);

    char buf[128];
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        const char *sep = " \n";
        char *cmd = strtok(buf, sep);
        char *address = strtok(NULL, sep);
        char *type = strtok(NULL, sep);
        char *size = strtok(NULL, sep);
        if (cmd == NULL) continue;
        if (strcmp(cmd, "block") == 0) {
            attack_t attack;
            unsigned int subnet;
            if (!fill_attack(&attack, &subnet, address, type, size)) {
                fprintf(stderr, "%s: Invalid arguments to block\n", name);
                exit(65);
            }
            fw_block(&attack, subnet);
        } else if (strcmp(cmd, "release") == 0) {
            attack_t attack;
            unsigned int subnet;
            if (!fill_attack(&attack, &subnet, address, type, size)) {
                fprintf(stderr, "%s: Invalid arguments to release\n", name);
                exit(65);
            }
            fw_release(&attack, subnet);
        } else if (strcmp(cmd, "flush") == 0) {
            fw_flush();
        } else if (strcmp(cmd, "flushonexit") == 0) {
            atexit((void (*)(void))fw_flush);
        } else {
            fprintf(stderr, "%s: Invalid command\n", name);
            exit(65);
        }
    }
}

int main() {
    backend_main("sshg-fw-hosts");
    return 0;
}
