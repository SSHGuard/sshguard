IPFW_TABLE=22

fw_init() {
    ipfw table ${IPFW_TABLE} list > /dev/null
}

fw_block() {
    ipfw table ${IPFW_TABLE} add $1
}

fw_release() {
    ipfw table ${IPFW_TABLE} delete $1
}

fw_flush() {
    ipfw table ${IPFW_TABLE} flush
}

fw_fin() {
    :
}
