#!/bin/sh
#
# PROVIDE: sshguard
# REQUIRE: LOGIN
# KEYWORD: shutdown
#
# Add the following lines to /etc/rc.conf to enable sshguard:
# sshguard_enable (bool):	Set it to "YES" to enable sshguard.
#	 Default is "NO".
# sshguard_logfiles (path):	Set list of files to monitor.
#	 Default is "/var/log/auth.log".
# sshguard_flags (str):	 Flags passed to sshguard on startup.
#	 Default is "".
#
. /etc/rc.subr
name="sshguard"
rcvar=`set_rcvar`
load_rc_config $name
: ${sshguard_enable="NO"}
: ${sshguard_logfiles="/var/log/auth.log"}
: ${sshguard_flags=""}

pidfile="/var/run/sshguard.pid"
command="/usr/local/sbin/sshguard"
procname=${command}
start_cmd=${name}_start
stop_postcmd=${name}_poststop

sshguard_start() {
    # build logsucker arguments for list of files to monitor
    for logfl in $sshguard_logfiles
    do
        [ ! -r "${logfl}" ] && echo "file '${logfl}' inaccessible, will it show up later?"
        logsucker_args="$logsucker_args -l $logfl"
    done
    # add it to the other command line flags
    sshguard_flags="$logsucker_args $sshguard_flags"
    echo "Starting ${name} (monitoring: $sshguard_logfiles)."
    # start the program and save its PID for later use by rc.subr
    $command $sshguard_flags 2>&1 &
    echo $! > ${pidfile}
}

sshguard_poststop() {
    rm -f ${pidfile}
}
run_rc_command "$1"

