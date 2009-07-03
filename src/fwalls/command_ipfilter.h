#ifndef COMMAND_H
#define COMMAND_H

/* user-define backend ipfilter */
#include "../config.h"

#define COMMAND_INIT       "grep -qE '^##sshguard-begin##\n##sshguard-end##$' < " IPFILTER_CONFFILE
#define COMMAND_FIN        ""
#define COMMAND_BLOCK      "if test $SSHG_ADDRKIND != 4; then exit 1 ; fi ; TMP=`mktemp /tmp/ipfconf.XX` && awk '1 ; /^##sshguard-begin##$/ { print \"block in quick proto tcp from '\"$SSHG_ADDR\"' to any\" }' <" IPFILTER_CONFFILE " > $TMP && mv $TMP " IPFILTER_CONFFILE " && " IPFPATH "/ipf -Fa && " IPFPATH "/ipf -f " IPFILTER_CONFFILE
#define COMMAND_RELEASE    "if test $SSHG_ADDRKIND != 4; then exit 1 ; fi ; TMP=`mktemp /tmp/ipfconf.XX` && awk 'BEGIN { copy = 1 } copy ; /^##sshguard-begin##$/    { copy = 0 ; next } !copy { if ($0 !~ /'\"$SSHG_ADDR\"'.*/) print $0 } /^##sshguard-end##$/  { copy = 1 }' <" IPFILTER_CONFFILE " >$TMP && mv $TMP " IPFILTER_CONFFILE " && " IPFPATH "/ipf -Fa && " IPFPATH "/ipf -f " IPFILTER_CONFFILE
#define COMMAND_FLUSH      "TMP=`mktemp /tmp/ipfconf.XX` && awk 'BEGIN { copy = 1 } /^##sshguard-begin##$/ { print $0 ; copy = 0 } /^##sshguard-end##$/ { copy = 1 } copy' <" IPFILTER_CONFFILE " >$TMP ; mv $TMP " IPFILTER_CONFFILE " ; " IPFPATH "/ipf -Fa && " IPFPATH "/ipf -f " IPFILTER_CONFFILE
#endif
