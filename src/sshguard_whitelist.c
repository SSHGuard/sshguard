/*
 * Copyright (c) 2007,2008 Mij <mij@bitchx.it>
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
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "simclist.h"
#include "sshguard_log.h"
#include "sshguard_whitelist.h"

#define WHITELIST_SRCLINE_LEN       300

regex_t wl_ip4reg, wl_ip6reg, wl_hostreg;
list_t whitelist;

/* an address with mask */
typedef struct {
    int addrkind;
    union {
        struct {
            uint32_t address;
            uint32_t  mask;
        } ip4;  /* an IPv4 address w/ mask */
        struct {
            struct in6_addr address;
            struct in6_addr mask;
        } ip6;  /* an IPv6 address w/ mask */
    } address;
} addrblock_t;

size_t whitelist_meter(const void *el) { return sizeof(addrblock_t); }

int whitelist_conf_init(void) {
    /* IPv4 address regex */
    if (regcomp(&wl_ip4reg, "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})$", REG_EXTENDED) != 0) {
        return -1;
    }

    /* IPv6 address regex */
    if (regcomp(&wl_ip6reg, "^(((([a-fA-F0-9]{1,4}):){7}([a-fA-F0-9]{1,4}))|((([a-fA-F0-9]{1,4}))?::((([a-fA-F0-9]{1,4}):){1,5}(([a-fA-F0-9]{1,4})))?)|(::[fF0]{0,4}:)((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]([0-9])?)(.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]([0-9])?|0)){3}))$", REG_EXTENDED) != 0) {
        return -1;
    }

    /* hostname regex */
    if (regcomp(&wl_hostreg, "^([-a-z0-9]+\\.)*[-a-z0-9]+$", REG_EXTENDED) != 0) {
        whitelist_fin();
        return -1;
    }

    return 0;
}

int whitelist_conf_fin(void) {
    regfree(&wl_ip4reg);
    regfree(&wl_ip6reg);
    regfree(&wl_hostreg);
    return 0;
}

int whitelist_init(void) {
    list_init(&whitelist);
    list_attributes_copy(&whitelist, whitelist_meter, 1);
    
    return 0;
}

int whitelist_fin(void) {
    list_destroy(&whitelist);
    return 0;
}

int whitelist_file(char *filename) {
    FILE *src;
    char line[WHITELIST_SRCLINE_LEN];
    int lineno = 0;
    size_t len;


    src = fopen(filename, "r");
    if (src == NULL) {
        sshguard_log(LOG_ERR, "whitelist: unable to open input file %s: %s", filename, strerror(errno));
        return -1;
    }

    while (fgets(line, WHITELIST_SRCLINE_LEN, src) != NULL) {
        lineno++;
        /* handle comment lines */
        if (line[0] == '#' || line[0] == '\n') continue;
        /* strip trailing '\n' */
        len = strlen(line);
        if (len == 0) continue;
        if (line[len-1] == '\n') line[len-1] = '\0';
        /* handling line */
        if (whitelist_add(line) != 0) {
            sshguard_log(LOG_ERR, "whitelist: Unable to handle line %d from whitelist file \"%s\".", lineno, filename);
        }
    }
    fclose(src);

    return 0;
}


int whitelist_add(char *str) {
    char *pos;

    /* try address/mask first */
    if (regexec(&wl_ip4reg, str, 0, NULL, 0) == 0) {         /* plain IPv4 address */
        sshguard_log(LOG_DEBUG, "whitelist: add '%s' as plain IPv4.", str);
        return whitelist_add_ipv4(str);
    } else if (regexec(&wl_ip6reg, str, 0, NULL, 0) == 0) {            /* plain IPv6 address */
        sshguard_log(LOG_DEBUG, "whitelist: add '%s' as plain IPv6.", str);
        return whitelist_add_ipv6(str);
    } else if (regexec(&wl_hostreg, str, 0, NULL, 0) == 0) {        /* hostname to be resolved */
        sshguard_log(LOG_DEBUG, "whitelist: add '%s' as host.", str);
        return whitelist_add_host(str);
    } else if (strrchr(str, '/') != NULL) {                         /* CIDR form (net block) */
        char buf[ADDRLEN+5];
        unsigned int masklen;

        strncpy(buf, str, sizeof(buf));
        pos = strrchr(buf, '/');
        *pos = '\0';
        masklen = (unsigned int)strtol(pos+1, (char **)NULL, 10);
        if (masklen == 0 && pos[1] != '0') {
            sshguard_log(LOG_WARNING, "whitelist: mask specified as '/%s' makes no sense.", pos+1);
            return -1;
        }

        if (masklen == 0 && errno != EINVAL) {
            /* could not convert the mask to an integer value */
            sshguard_log(LOG_WARNING, "whitelist: could not parse line \"%s\" as plain IP nor IP block nor host name", str);
            return -1;
        }
        if (regexec(&wl_ip4reg, buf, 0, NULL, 0) == 0) {
            if (masklen > 32) {     /* sanity check for netmask */
                sshguard_log(LOG_WARNING, "whitelist: mask length '%u' makes no sense for IPv4.", masklen);
                return -1;
            }
            return whitelist_add_block4(buf, masklen);
        } else if (regexec(&wl_ip6reg, buf, 0, NULL, 0) == 0) {
            if (masklen > 128) {     /* sanity check for netmask */
                sshguard_log(LOG_WARNING, "whitelist: mask length '%u' makes no sense for IPv6.", masklen);
                return -1;
            }
            return whitelist_add_block6(buf, masklen);
        }
    } else {
        /* line not recognized */
        sshguard_log(LOG_WARNING, "whitelist: could not parse line \"%s\" as plain IP nor IP block nor host name", str);
        return -1;
    }

    return -1;
}

int whitelist_add_block4(char *address, int masklen) {
    addrblock_t ab;

    /* parse block line */
    ab.addrkind = ADDRKIND_IPv4;
    if (inet_pton(AF_INET, address, & ab.address.ip4.address) != 1) {
        sshguard_log(LOG_WARNING, "whitelist: could not intepret address '%s': %s.", address, strerror(errno));
        return -1;
    }
    ab.address.ip4.mask = htonl(0xFFFFFFFF << (32-masklen));

    list_append(& whitelist, &ab);
    sshguard_log(LOG_DEBUG, "whitelist: add block: %s with mask %d.", address, masklen);

    return 0;
}

int whitelist_add_block6(char *address, int masklen) {
    sshguard_log(LOG_WARNING, "whitelist: IPv6 block whitelisting not yet supported, skipping...");
    return -1;
}

int whitelist_add_ipv4(char *ip) {
    addrblock_t ab;

    ab.addrkind = ADDRKIND_IPv4;
    inet_pton(AF_INET, ip, & ab.address.ip4.address);
    ab.address.ip4.mask = 0xFFFFFFFF;

    list_append(&whitelist, & ab);
    sshguard_log(LOG_DEBUG, "whitelist: add plain ip %s.", ip);
    return 0;
}

int whitelist_add_ipv6(char *ip) {
    addrblock_t ab;
    int i;

    ab.addrkind = ADDRKIND_IPv6;

    if (inet_pton(AF_INET6, ip, &ab.address.ip6.address.s6_addr) != 1) {
        sshguard_log(LOG_ERR, "whitelist: add ipv6: Could not add %s.", ip);
        return -1;
    }

    for (i = 0; i < sizeof(struct in6_addr); i++)
        ab.address.ip6.mask.s6_addr[i] = 0xFF;

    list_append(&whitelist, & ab);
    sshguard_log(LOG_DEBUG, "whitelist: add plain ip %s.", ip);
    return 0;
}

int whitelist_add_host(char *host) {
    addrblock_t ab;
    struct hostent *he;
    int i;

    he = gethostbyname(host);
    if (he == NULL) {
        /* could not resolve hostname */
        sshguard_log(LOG_ERR, "Could not resolve hostname '%s'!", host);
        return -1;
    }
    for (i = 0; he->h_addr_list[i] != NULL; i++) {
        ab.addrkind = ADDRKIND_IPv4;
        ab.address.ip4.mask = 0xFFFFFFFF;
        memcpy(& ab.address.ip4.address, he->h_addr_list[i], he->h_length);
        list_append(&whitelist, &ab);
    }

    sshguard_log(LOG_DEBUG, "whitelist: add hostname '%s' with %d addresses.", host, i);
    
    return 0;
}

int whitelist_match(char *addr, int addrkind) {
    uint32_t addrent;
    struct in6_addr addrent6;
    int i, j;
    addrblock_t *entry;

    switch (addrkind) {
        case ADDRKIND_IPv4:
            if (inet_pton(AF_INET, addr, &addrent) != 1) {
                sshguard_log(LOG_WARNING, "whitelist: could not interpret ip address '%s'.", addr);
                return 0;
            }
            break;
        case ADDRKIND_IPv6:
            if (inet_pton(AF_INET6, addr, &addrent6.s6_addr) != 1) {
                sshguard_log(LOG_WARNING, "whitelist: could not interpret ip address '%s'.", addr);
                return 0;
            }
            break;
        default:       /* not recognized */
            return 0;
    }

    /* compare with every entry in the list */
    for (i = 0; (unsigned int)i < list_size(&whitelist); i++) {
        entry = (addrblock_t *)list_get_at(&whitelist, i);
        if (addrkind != entry->addrkind) continue;
        switch (entry->addrkind) {
            case ADDRKIND_IPv4:
                if ((entry->address.ip4.address & entry->address.ip4.mask) == (addrent & entry->address.ip4.mask)) {
                    return 1;
                }
                break;
            case ADDRKIND_IPv6:
                for (j = 0; j < sizeof(addrent6); j++) {
                    if ((entry->address.ip6.address.s6_addr[j] & entry->address.ip6.mask.s6_addr[j]) != (addrent6.s6_addr[j] & entry->address.ip6.mask.s6_addr[j]))
                        return 0; 
                }
                return 1;
            default:
                return 0;
        }
    }
    return 0;
}
