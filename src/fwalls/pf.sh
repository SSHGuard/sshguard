fw_init() {
    pfctl -t sshguard -T show > /dev/null
}

fw_block() {
    pfctl -k $1 -t sshguard -T add $1
}

fw_release() {
    pfctl -t sshguard -T del $1
}

fw_flush() {
    pfctl -t sshguard -T flush
}

fw_fin() {
}
