fw_init() {
    pfctl -q -t sshguard -T show > /dev/null
}

fw_block() {
    pfctl -q -k $1 -t sshguard -T add $1
}

fw_release() {
    pfctl -q -t sshguard -T del $1
}

fw_flush() {
    pfctl -q -t sshguard -T flush
}

fw_fin() {
    :
}
