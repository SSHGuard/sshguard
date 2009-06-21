#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <simclist.h>

#include "../config.h"
#include "../sshguard_log.h"
#include "../sshguard_fw.h"
#include "../sshguard_services.h"

#ifndef HOSTSFILE_PATH
#   define HOSTSFILE_PATH     "/etc/hosts.allow"
#endif
#define HOSTS_MAXCMDLEN       1024

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

size_t addr_service_meter(const void *el) { return sizeof(addr_service_t); }
int addr_service_comparator(const void *a, const void *b) {
    addr_service_t *A = (addr_service_t *)a;
    addr_service_t *B = (addr_service_t *)b;
    return !((strcmp(A->addr, B->addr) == 0) && (A->addrkind == B->addrkind) && (A->service == B->service));
}

int fw_init() {
    char buf[HOSTS_MAXCMDLEN];
    char tempflname[30];
    FILE *tmp, *deny;
    int fd;

    hosts_clearsshguardblocks();

    /* place sshguard block delimiters (header/footer) into HOSTSFILE_PATH */
    deny = fopen(HOSTSFILE_PATH, "r+");
    if (deny == NULL) {
        sshguard_log(LOG_ERR, "Could not initialize " HOSTSFILE_PATH " for use by sshguard: %s", strerror(errno));
        return FWALL_ERR;
    }

    strcpy(tempflname, "/tmp/sshguard.deny.XXXXXX");
    if ((fd = mkstemp(tempflname)) == -1) {
        sshguard_log(LOG_ERR, "Could not create temporary file %s!", tempflname);
        return FWALL_ERR;
    }
    tmp = fdopen(fd, "a+");
    fprintf(tmp, "%s%s", HOSTS_SSHGUARD_PREFIX, HOSTS_SSHGUARD_SUFFIX);

    /* copy the original content of HOSTSFILE_PATH into tmp */
    while (fgets(buf, HOSTS_MAXCMDLEN, deny) != NULL) {
        fprintf(tmp, "%s", buf);
    }
    
    rewind(tmp);
    rewind(deny);
    while (fgets(buf, HOSTS_MAXCMDLEN, tmp) != NULL) {
        fprintf(deny, "%s", buf);
    }

    fclose(tmp);
    fclose(deny);
    unlink(tempflname);

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

int fw_block(char *addr, int addrkind, int service) {
	addr_service_t ads;
		
	strcpy(ads.addr, addr);
	ads.service = service;
	ads.addrkind = addrkind;
	list_append(&hosts_blockedaddrs, &ads);

	return hosts_updatelist();
}

int fw_release(char *addr, int addrkind, int services) {
    int pos;

    if (addrkind != ADDRKIND_IPv4) return FWALL_UNSUPP;
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
    int fd;
    char buf[HOSTS_MAXCMDLEN];
    char tempflname[30];
    FILE *tmp, *deny;

    /* open hosts.allow file */
    deny = fopen(HOSTSFILE_PATH, "r+");
    if (deny == NULL) {
        sshguard_log(LOG_ERR, "Could not open hosts.allow file " HOSTSFILE_PATH);
        return FWALL_ERR;
    }

    /* create/open a temporary file */
    strcpy(tempflname, "/tmp/sshguard.hosts.XXXXXX");
    if ((fd = mkstemp(tempflname)) == -1) {
        sshguard_log(LOG_ERR, "Could not create temporary file %s!", tempflname);
        fclose(deny);
        return FWALL_ERR;
    }
    tmp = fdopen(fd, "a+");
    
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
        close(fd);
        unlink(tempflname);
        return FWALL_ERR;
    }

    if (list_size(& hosts_blockedaddrs) > 0) {
        unsigned int cnt;
		addr_service_t *curr;

        for (cnt = 0; cnt < (int)list_size(&hosts_blockedaddrs); cnt++) {
			curr = (addr_service_t *)list_get_at(&hosts_blockedaddrs, cnt);
			
			/* block based on service */
			switch (curr->service) {
    	        case SERVICES_SSH:
			        fprintf(tmp, "sshd :");
        	    	break;
				case SERVICES_UWIMAP:
					fprintf(tmp, "imapd :");
					break;
				case SERVICES_DOVECOT:
					fprintf(tmp, "imap-login, pop3-login :");
					break;
				case SERVICES_CYRUSIMAP:
					fprintf(tmp, "imapd, pop3d :");
					break;
				case SERVICES_FREEBSDFTPD:
					fprintf(tmp, "ftpd :");
					break;
				case SERVICES_PROFTPD:
					fprintf(tmp, "proftpd :");
					break;
				case SERVICES_PUREFTPD:
					fprintf(tmp, "pure-ftpd :");
					break;
				default:
					sshguard_log(LOG_ERR, "Attempting to block unknown service: %d", curr->service);
        			fclose(deny);
        			fclose(tmp);
        			close(fd);
        			unlink(tempflname);
        			return FWALL_ERR;        	
			}
			fprintf(tmp, " %s : DENY\n", curr->addr);
        }
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
        close(fd);
        unlink(tempflname);
        return FWALL_ERR;
    }

    /* copy the rest of the original file */
    while (fgets(buf, HOSTS_MAXCMDLEN, deny)) {
        fprintf(tmp, "%s", buf);
    }

    /* move tmp over to deny */
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

    return FWALL_OK;
}

int hosts_clearsshguardblocks(void) {
    char tempflname[30];
    char buf[HOSTS_MAXCMDLEN];
    int docopy;
    FILE *tmp, *deny;

    /* open deny file */
    deny = fopen(HOSTSFILE_PATH, "r+");
    if (deny == NULL) {
        sshguard_log(LOG_ERR, "unable to open temporary file %s: %s", tempflname, strerror(errno));
        return FWALL_ERR;
    }

    /* open temporary file */
    strcpy(tempflname, "/tmp/sshguard.deny.XXXXXX");
    if ((docopy = mkstemp(tempflname)) == -1) {
        sshguard_log(LOG_ERR, "Could not get temporary file from /tmp: %s", strerror(errno));
        return FWALL_ERR;
    }
    tmp = fdopen(docopy, "a+");

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

    /* move tmp over to deny */
    rewind(tmp);
    rewind(deny);
    while(fgets(buf, HOSTS_MAXCMDLEN, tmp) != NULL) {
        fprintf(deny, "%s", buf);
    }
    ftruncate(fileno(deny), ftell(tmp));
    fclose(tmp);
    fclose(deny);
    unlink(tempflname);

    return FWALL_OK;
}
