run_iptables() {
    cmd=iptables
    if [ "6" = "$2" ]; then
        cmd=ip6tables
    fi

    # Check if iptables supports the '-w' flag.
    if $cmd -w -V >/dev/null 2>&1; then
        $cmd -w $1
    else
        $cmd $1
    fi
}

fw_init() {
    run_iptables "-L -n"
}

fw_block() {
    run_iptables "-I sshguard -s $1 -j DROP" $2
}

fw_release() {
    run_iptables "-D sshguard -s $1 -j DROP" $2
}

fw_flush() {
    run_iptables "-F sshguard" 4
    run_iptables "-F sshguard" 6
}

fw_fin() {
    :
}
