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

#ifndef COMMAND_H
#define COMMAND_H

/* sample command.h content for netfilter/iptables */


#include "../config.h"

/* for initializing the firewall (+ make sure we have sufficient credentials) */
#define COMMAND_INIT        "iptables -L"

/* for finalizing the firewall */
#define COMMAND_FIN         ""

/* for blocking an IP */
/* the command will have the following variables in its environment:
 *  $SSHG_ADDR      the address to operate (e.g. 192.168.0.12)
 *  $SSHG_ADDRKIND  the code of the address type [see sshguard_addresskind.h] (e.g. 4)
 *  $SSHG_SERVICE   the code of the service attacked [see sshguard_services.h] (e.g. 10)
 */
#define COMMAND_BLOCK       "case $SSHG_ADDRKIND in 4) exec " IPTABLES_PATH "/iptables -I sshguard -s $SSHG_ADDR -j DROP ;; 6) exec " IPTABLES_PATH "/ip6tables -I sshguard -s $SSHG_ADDR -j DROP ;; *) exit -2 ;; esac"

/* iptables does not support blocking multiple addresses in one call.
 * COMMAND_BLOCK_LIST can not be provided here, a sequence of calls to
 * COMMAND_BLOCK will be automatically used instead */

/* for releasing a blocked IP */
/* the command will have the following variables in its environment:
 *  $SSHG_ADDR      the address to operate (e.g. 192.168.0.12)
 *  $SSHG_ADDRKIND  the code of the address type [see sshguard_addresskind.h] (e.g. 4)
 *  $SSHG_SERVICE   the code of the service attacked [see sshguard_services.h] (e.g. 10)
 */
#define COMMAND_RELEASE     "case $SSHG_ADDRKIND in 4) exec " IPTABLES_PATH "/iptables -D sshguard -s $SSHG_ADDR -j DROP ;; 6) exec " IPTABLES_PATH "/ip6tables -D sshguard -s $SSHG_ADDR -j DROP ;; *) exit -2 ;; esac"

/* for releasing all blocked IPs at once (blocks flush) */
#define COMMAND_FLUSH       IPTABLES_PATH "/iptables -F sshguard ; " IPTABLES_PATH "/ip6tables -F sshguard"


#endif

