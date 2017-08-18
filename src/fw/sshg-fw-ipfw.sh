#!/bin/sh
# sshg-fw-ipfw
# This file is part of SSHGuard.

IPFW_TABLE=22

fw_init() {
    # Starting in FreeBSD 11, tables must first be created.
    ipfw table ${IPFW_TABLE} create 2>/dev/null || \
        ipfw table ${IPFW_TABLE} list > /dev/null
}

fw_block() {
    ipfw table ${IPFW_TABLE} add $1/$3
}

fw_release() {
    ipfw table ${IPFW_TABLE} delete $1/$3
}

fw_flush() {
    ipfw table ${IPFW_TABLE} flush
}

fw_fin() {
    ipfw table ${IPFW_TABLE} destroy 2>/dev/null
}
