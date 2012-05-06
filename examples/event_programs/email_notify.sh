#! /bin/sh

## Send an email notification for relevant events.
## See http://sshguard.net .

# space-separated list of email addresses to notify
notification_recipient_emails="root@localhost admin@localhost"

# space-separated list of service codes to notify about (others are ignored).
# see http://www.sshguard.net/docs/reference/service-codes/ for the full list.
notification_service_codes="100 250"

# include server name in notifications, for reference
server_name=`uname -n`

# call this function to run the actual firewall command and 
# return its exit status (as our own) up to SSHGuard
runfw_and_exit () {
    exec $SSHG_FWCMD
    exit 0      # won't be called unless $SSHG_FWCMD was empty
}


# use this structure to decide what to do on relevant and irrelevant events
case "$SSHG_ACTION" in
    block)
        ;;

    # we do not care about block_list either: never called for real-time blocks.

    *)
        runfw_and_exit
        ;;
esac

# only do it for the services we care about
if echo $notification_service_codes | grep -qE '(^| )'$SSHG_SERVICE'( |$)' ; then
    echo "Sending email notification to $notification_recipient_emails"
    mail -s "[SSHGuard] $server_name attacked on service #$SSHG_SERVICE" $notification_recipient_emails <<EOF
Attack details:

* Attacker address: $SSHG_ADDR (IPv$SSHG_ADDRKIND)
* Service code: $SSHG_SERVICE    (see http://www.sshguard.net/docs/reference/service-codes/ )
* Time: `date`
EOF
fi

# terminate by running $SSHG_FWCMD and returning its exit status
runfw_and_exit

