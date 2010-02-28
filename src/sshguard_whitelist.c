/*
 * Copyright (c) 2007,2008,2010 Mij <mij@bitchx.it>
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
#include <assert.h>

#include "simclist.h"
#include "sshguard_log.h"
#include "regexlib.h"
#include "sshguard_whitelist.h"

#define WHITELIST_SRCLINE_LEN       300

/* number of bits in the address types */
#define IPV4_BITS                   32
#define IPV6_BITS                   128


regex_t wl_ip4reg, wl_ip6reg, wl_hostreg;
list_t whitelist;

/* an address with mask */
typedef struct {
    int addrkind;
    union {
        struct {
            in_addr_t address;
            in_addr_t mask;
        } ip4;  /* an IPv4 address w/ mask */
        struct {
            struct in6_addr address;
            struct in6_addr mask;
        } ip6;  /* an IPv6 address w/ mask */
    } address;
} addrblock_t;


/* tell if IPv4 addr1 and addr2 are equivalent modulo mask */
static int match_ip4(in_addr_t addr1, in_addr_t addr2, in_addr_t mask) {
    return ((addr1 & mask) == (addr2 & mask)) ? 1 : 0;
}

/* tell if IPv6 addr1 and addr2 are equivalent modulo mask */
static int match_ip6(const struct in6_addr *restrict addr1, const struct in6_addr *restrict addr2, const struct in6_addr *restrict mask) {
    int i;

    for (i = 0; i < sizeof(addr1->s6_addr) && mask->s6_addr[i] != 0; i++) {
        if ((addr1->s6_addr[i] & mask->s6_addr[i]) != (addr2->s6_addr[i] & mask->s6_addr[i]))
            return 0;
    }

    return 1;
}


static size_t whitelist_meter(const void *el) { return sizeof(addrblock_t); }

int whitelist_conf_init(void) {
    /* IPv4 address regex */
    if (regcomp(&wl_ip4reg, "^" REGEXLIB_IPV4 "$", REG_EXTENDED) != 0) {
        return -1;
    }

    /* IPv6 address regex */
    if (regcomp(&wl_ip6reg, "^" REGEXLIB_IPV6 "$", REG_EXTENDED) != 0) {
        return -1;
    }

    /* hostname regex */
    if (regcomp(&wl_hostreg, "^" REGEXLIB_HOSTNAME "$", REG_EXTENDED) != 0) {
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

int whitelist_file(const char *restrict filename) {
    FILE *src;
    char line[WHITELIST_SRCLINE_LEN];
    int lineno = 0;
    size_t len;


    if (filename == NULL) return -1;

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


int whitelist_add(const char *str) {
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
        char *pos;
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
            if (masklen > IPV4_BITS) {     /* sanity check for netmask */
                sshguard_log(LOG_WARNING, "whitelist: mask length '%u' makes no sense for IPv4.", masklen);
                return -1;
            }
            if (masklen == IPV4_BITS) {
                /* de-genere case with full mask --> plain address */
                return whitelist_add_ipv4(buf);
            }
            return whitelist_add_block4(buf, masklen);
        } else if (regexec(&wl_ip6reg, buf, 0, NULL, 0) == 0) {
            if (masklen > IPV6_BITS) {     /* sanity check for netmask */
                sshguard_log(LOG_WARNING, "whitelist: mask length '%u' makes no sense for IPv6.", masklen);
                return -1;
            }
            if (masklen == IPV6_BITS) {
                /* de-genere case with full mask --> plain address */
                return whitelist_add_ipv6(buf);
            }
            return whitelist_add_block6(buf, masklen);
        }
    } else {
        /* line not recognized */
        sshguard_log(LOG_WARNING, "whitelist: could not parse line \"%s\" as plain IP nor IP block nor host name.", str);
        return -1;
    }

    return -1;
}

int whitelist_add_block4(const char *restrict address, int masklen) {
    addrblock_t ab;

    /* parse block line */
    ab.addrkind = ADDRKIND_IPv4;
    if (inet_pton(AF_INET, address, & ab.address.ip4.address) != 1) {
        sshguard_log(LOG_WARNING, "whitelist: could not interpret address '%s': %s.", address, strerror(errno));
        return -1;
    }
    ab.address.ip4.mask = htonl(0xFFFFFFFF << (IPV4_BITS-masklen));

    list_append(& whitelist, &ab);
    sshguard_log(LOG_DEBUG, "whitelist: add IPv4 block: %s with mask %d.", address, masklen);

    return 0;
}

int whitelist_add_block6(const char *restrict address, int masklen) {
    addrblock_t ab;
    int bytelen, bitlen;
    uint8_t bitmask;

    /* parse block line */
    ab.addrkind = ADDRKIND_IPv6;
    if (inet_pton(AF_INET6, address, & ab.address.ip6.address.s6_addr) != 1) {
        sshguard_log(LOG_WARNING, "whitelist: could not interpret address '%s': %s.", address, strerror(errno));
        return -1;
    }

    bytelen = masklen / 8;
    /* compile the "all 1s" part */
    memset(ab.address.ip6.mask.s6_addr, 0xFF, bytelen);
    /* compile the "crossing byte" */
    if (bytelen == sizeof(ab.address.ip6.mask.s6_addr))
        return 0;

    /* compile the remainder "all 0s" part */
    bitlen = masklen % 8;
    bitmask = 0xFF << (8 - bitlen);
    ab.address.ip6.mask.s6_addr[bytelen] = bitmask;
    memset(& ab.address.ip6.mask.s6_addr[bytelen+1], 0x00, sizeof(ab.address.ip6.mask.s6_addr) - bytelen);

    list_append(& whitelist, &ab);
    sshguard_log(LOG_DEBUG, "whitelist: add IPv6 block: %s with mask %d.", address, masklen);

    return 0;
}

int whitelist_add_ipv4(const char *restrict ip) {
    addrblock_t ab;

    ab.addrkind = ADDRKIND_IPv4;
    inet_pton(AF_INET, ip, & ab.address.ip4.address);
    ab.address.ip4.mask = 0xFFFFFFFF;

    list_append(&whitelist, & ab);
    sshguard_log(LOG_DEBUG, "whitelist: add plain IPv4 %s.", ip);
    return 0;
}

int whitelist_add_ipv6(const char *restrict ip) {
    addrblock_t ab;

    ab.addrkind = ADDRKIND_IPv6;

    if (inet_pton(AF_INET6, ip, &ab.address.ip6.address.s6_addr) != 1) {
        sshguard_log(LOG_ERR, "whitelist: add ipv6: Could not add %s.", ip);
        return -1;
    }

    memset(ab.address.ip6.mask.s6_addr, 0xFF, sizeof(ab.address.ip6.mask.s6_addr));

    list_append(&whitelist, & ab);
    sshguard_log(LOG_DEBUG, "whitelist: add plain IPv6 %s.", ip);
    return 0;
}

int whitelist_add_host(const char *restrict host) {
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
    /* TODO: add IPv6 addresses too, if any! */

    sshguard_log(LOG_DEBUG, "whitelist: add hostname '%s' with %d addresses.", host, i);
    
    return 0;
}

int whitelist_match(const char *restrict addr, int addrkind) {
    in_addr_t addrent;
    struct in6_addr addrent6;
    addrblock_t *entry;

    switch (addrkind) {
        case ADDRKIND_IPv4:
            if (inet_pton(AF_INET, addr, &addrent) != 1) {
                sshguard_log(LOG_WARNING, "whitelist: could not interpret ip address '%s'.", addr);
                return 0;
            }
            /* compare with every IPv4 entry in the list */
            list_iterator_start(&whitelist);
            while (list_iterator_hasnext(&whitelist)) {
                entry = (addrblock_t *)list_iterator_next(&whitelist);
                if (entry->addrkind != ADDRKIND_IPv4)
                    continue;
                if (match_ip4(addrent, entry->address.ip4.address, entry->address.ip4.mask)) {
                    return 1;
                }
            }
            list_iterator_stop(&whitelist);
            break;

        case ADDRKIND_IPv6:
            if (inet_pton(AF_INET6, addr, &addrent6.s6_addr) != 1) {
                sshguard_log(LOG_WARNING, "whitelist: could not interpret ip address '%s'.", addr);
                return 0;
            }
            /* compare with every IPv6 entry in the list */
            list_iterator_start(&whitelist);
            while (list_iterator_hasnext(&whitelist)) {
                entry = (addrblock_t *)list_iterator_next(&whitelist);
                if (entry->addrkind != ADDRKIND_IPv6)
                    continue;
                if (match_ip6(&addrent6, &entry->address.ip6.address, &entry->address.ip6.mask)) {
                    return 1;
                }
            }
            list_iterator_stop(&whitelist);
            break;

        default:       /* not recognized */
            /* make errors apparent */
            assert(0);
    }

    return 0;
}
