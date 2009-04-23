#ifndef COMMAND_H
#define COMMAND_H

/* sample command.h content for netfilter/iptables */


#include "../config.h"

/* for initializing the firewall */
#define COMMAND_INIT        ""

/* for finalizing the firewall */
#define COMMAND_FIN         ""

/* for blocking an IP */
/* the command will have the following variables in its environment:
 *  $SSHG_ADDR      the address to operate (e.g. 192.168.0.12)
 *  $SSHG_ADDRKIND  the code of the address type [see sshguard_addresskind.h] (e.g. 4)
 *  $SSHG_SERVICE   the code of the service attacked [see sshguard_services.h] (e.g. 10)
 */
#define COMMAND_BLOCK       "case $SSHG_ADDRKIND in 4) exec " IPTABLES_PATH "/iptables -I sshguard -s $SSHG_ADDR -j DROP ;; 6) exec " IPTABLES_PATH "/ip6tables -I sshguard -s $SSHG_ADDR -j DROP ;; *) exit -2 ;; esac"

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

