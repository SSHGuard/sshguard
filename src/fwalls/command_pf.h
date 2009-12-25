#ifndef COMMAND_H
#define COMMAND_H

/* sample command.h content for OpenBSD's PF firewall */


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
#define COMMAND_BLOCK       PFCTL_PATH "/pfctl -Tadd -t sshguard $SSHG_ADDR"

/* for blocking a comma-separated list of IPs */
/* the command will have the following variables in its environment:
 *  $SSHG_ADDR      the comma-separated list of address to operate (e.g. 192.168.0.12,1.2.3.4,143.123.176.2)
 *  $SSHG_ADDRKIND  the code of the address type [see sshguard_addresskind.h] (e.g. 4)
 *  $SSHG_SERVICE   the code of the service attacked [see sshguard_services.h] (e.g. 10)
 */
#define COMMAND_BLOCK_LIST  PFCTL_PATH "/pfctl -Tadd -t sshguard `echo $SSHG_ADDR | tr ',' ' '`"

/* for releasing a blocked IP */
/* the command will have the following variables in its environment:
 *  $SSHG_ADDR      the address to operate (e.g. 192.168.0.12)
 *  $SSHG_ADDRKIND  the code of the address type [see sshguard_addresskind.h] (e.g. 4)
 *  $SSHG_SERVICE   the code of the service attacked [see sshguard_services.h] (e.g. 10)
 */
#define COMMAND_RELEASE     PFCTL_PATH "/pfctl -Tdel -t sshguard $SSHG_ADDR"

/* for releasing all blocked IPs at once (blocks flush) */
#define COMMAND_FLUSH       PFCTL_PATH "/pfctl -Tflush -t sshguard"


#endif

