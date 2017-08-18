#!/bin/sh
# sshg-fw-ipfilter
# This file is part of SSHGuard.

IPFILTER_CMD=ipf
IPFILTER_CONF=/etc/ipfilter.conf

fw_init() {
    :
}

fw_block() {
    FAM=""
    if [ -n "$2" ]; then
        FAM="-$2"
    fi
    echo "block in quick proto tcp from $1/$3 to any" | \
        ${IPFILTER_CMD} ${FAM} -A -f -
}

fw_release() {
    FAM=""
    if [ -n "$2" ]; then
        FAM="-$2"
    fi
    echo "block in quick proto tcp from $1/$3 to any" | \
        ${IPFILTER_CMD} ${FAM} -A -r -f -
}

fw_flush() {
    ${IPFILTER_CMD} -Fa && ${IPFILTER_CMD} -f ${IPFILTER_CONF}
}

fw_fin() {
    :
}
