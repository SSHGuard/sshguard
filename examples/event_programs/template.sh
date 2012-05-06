#! /bin/sh

## Template for SSHGuard Event Programs.
## See http://sshguard.net .
## Author: mij@sshguard.net , year 2012.


# call this function to run the actual firewall command and 
# return its exit status (as our own) up to SSHGuard
runfw_and_exit () {
    exec $SSHG_FWCMD
    exit 0      # won't be called unless $SSHG_FWCMD was empty
}


# use this structure to decide what to do on relevant and irrelevant events
case "$SSHG_ACTION" in
    init)
        ;;

    block|block_list)
        ;;

    release)
        ;;

    fin)
        ;;

    flush)
        ;;

    *)
        # all other cases (this should never be reached)
        ;;
esac

# do custom stuff here
## echo "Hello world!"

# terminate by running $SSHG_FWCMD and returning its exit status
runfw_and_exit
