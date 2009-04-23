#ifndef COMMAND_H
#define COMMAND_H

/* sample command.h content for AIX's genfilt firewall */


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
#define COMMAND_BLOCK       FILT_PATH "/genfilt -v 4  -a D -s $SSHG_ADDR -m 255.255.255.255 -d 0.0.0.0 -M 0.0.0.0 -g y -c all -o any -p 0 -O any -P 0 -r B -w B -l N -f y -t 0 -i all  -D sshguard && " FILT_PATH "/mkfilt -v 4 -u"

/* for releasing a blocked IP */
/* the command will have the following variables in its environment:
 *  $SSHG_ADDR      the address to operate (e.g. 192.168.0.12)
 *  $SSHG_ADDRKIND  the code of the address type [see sshguard_addresskind.h] (e.g. 4)
 *  $SSHG_SERVICE   the code of the service attacked [see sshguard_services.h] (e.g. 10)
 */
#define COMMAND_RELEASE     FILT_PATH "/rmfilt -v 4 -n`" FILT_PATH "/lsfilt -s -v 4 -O | grep \"deny $SSHG_ADDR 255.255.255.255\" | awk -F' ' -- '{print $1}'` && " FILT_PATH "/mkfilt -v 4 -u"

/* for releasing all blocked IPs at once (blocks flush) */
#define COMMAND_FLUSH       "for I in `" FILT_PATH "/lsfilt -s -v 4 -O -d | grep sshguard | awk -F' ' -- '{print $1}'` ; do " FILT_PATH "/rmfilt -v 4 -n$I ; done && " FILT_PATH "/mkfilt -v 4 -u"


#endif

