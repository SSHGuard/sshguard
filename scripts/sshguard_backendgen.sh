#! /bin/sh

cat <<-UserMessage
This script lets you generate command backends for sshguard easily.
A command-based backend is one that uses commands for blocking,
releasing, flushing block rules.

I need the following:
 - a name for this backend (choose yourself)
 - [possibly] a command for first inizialization of the backend
 - a command for blocking an address
 - a command for releasing an address
 - a command for flushing the blocked addresses
 - [possibly] a command for last finalization of the backend
These can all be composite with shell operators.
Press enter to continue, Ctrl-C to exit.
UserMessage

read


##############
# $1 =  fwall name
# $2 =  init commands
# $3 =  blocking commands
# $4 =  releasing commands
# $5 =  flushing commands
# $6 =  finalizing commands
gen_template () {
cat >command_${1}.h <<-EOF
#ifndef COMMAND_H
#define COMMAND_H

/* user-define backend $1 */
#include "../config.h"

#define COMMAND_INIT       "$2"
#define COMMAND_FIN        "$6"
#define COMMAND_BLOCK      "$3"
#define COMMAND_RELEASE    "$4"
#define COMMAND_FLUSH      "$5"
        
#endif
EOF
}


genhttp () {
    printf "fwname=%s&init=%s&fin=%s&block=%s&release=%s&flush=%s" "$1" "$2" "$6" "$3" "$4" "$5"
}
##############


# read name
echo -n "1) name (choose yourself): "
read fwname
# read init command(s)
echo -n "2) initialization command(s) (leave empty for no init commands): "
read fwinitcmd
# read blocking command(s)
echo "3) blocking command(s)"
cat <<-msg
The following variables are available in the environment of this command:
    \$SSHG_ADDR       the address to operate (e.g. 192.168.0.12)
    \$SSHG_ADDRKIND   the code of the address type [see sshguard_addresskind.h] (e.g. 2)
    \$SSHG_SERVICE    the code of the service attacked [see sshguard_services.h] (e.g. 10)
msg
read fwblockcmd
while test "x$fwblockcmd" = x ; do
    echo -n "*need* to specify blocking command(s) (Ctrl-C to exit): "
    read fwblockcmd
done
# read releasing command(s)
echo "4) releasing command(s): "
cat <<-msg
The following variables are available in the environment of this command:
    \$SSHG_ADDR       the address to operate (e.g. 192.168.0.12)
    \$SSHG_ADDRKIND   the code of the address type [see sshguard_addresskind.h] (e.g. 2)
    \$SSHG_SERVICE    the code of the service attacked [see sshguard_services.h] (e.g. 10)
msg
read fwreleasecmd
while test "x$fwreleasecmd" = x ; do
    echo -n "*need* to specify releasing command(s) (Ctrl-C to exit): "
    read fwreleasecmd
done
# read flush command(s)
echo -n "5) flushing command(s): "
read fwflushcmd
while test "x$fwflushcmd" = x ; do
    echo -n "*need* to specify flushing command(s) (Ctrl-C to exit): "
    read
done
# read finalization command(s)
echo -n "6) finalization command(s) (leave empty for none): "
read fwfincmd

echo "Result ======================================================="
printf "name: %s\ninit: %s\nblock: %s\nrelease: %s\nflush %s\nfin: %s\n" "$fwname" "$fwinitcmd" "$fwblockcmd" "$fwreleasecmd" "$fwflushcmd" "$fwfincmd"
echo -n "Confirm? Enter for yes, Ctrl-C to exit: "
read
echo -n "Generating backend as command_${fwname}.h ..."

gen_template "$fwname" "$fwinitcmd" "$fwblockcmd" "$fwreleasecmd" "$fwflushcmd" "$fwfincmd"

echo " done!"
echo "Do you want me to anonymously submit this to http://www.sshguard.net/newfw.php ? [y/n]"
read response

if test "x$response" = xn ; then echo "Not submitting, and terminating." ; exit 0 ; fi

# submitting backend
echo "Submitting ... "
if ! hash curl 2>/dev/null ; then
    echo "Could not submit: did not find curl in PATH."
    exit 2
fi

curl --silent -F"fwname=$fwname" -F"init=$fwinitcmd" -F"fin=$fwfincmd" -F"block=$fwblockcmd" -F"release=$fwreleasecmd" -F"flush=$fwflushcmd" http://www.sshguard.net/newfw.php >/dev/null
if test $? -ne 0 ; then
    echo "curl failed while submitting."
    exit 3
fi

echo "Submitted successfully. Thanks"

