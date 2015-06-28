run_iptables() {
    cmd=iptables
    if [ "$2" == "6" ]; then
        cmd=ip6tables
    fi

    $cmd -w $1
    ret=$?
    if [ $ret -eq 2 ]; then
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
}
