#!/bin/sh
# sshg-fw-ipfilter
# This file is part of SSHGuard.

IPFILTER_CONF=/etc/ipfilter.conf
IPFILTER_PATH=/sbin/ipf

fw_init() {
    grep -E '^##sshguard-begin##\n##sshguard-end##$' \
        < ${IPFILTER_CONF} >/dev/null 2>/dev/null
}

fw_block() {
    if test $SSHG_ADDRKIND != 4; then
        return 1
    fi
    TMP=`mktemp /tmp/ipfconf.XXXXX`
    awk '1 ; /^##sshguard-begin##$/ { print \"block in quick proto tcp from '\"$SSHG_ADDR\"' to any\" }' < ${IPFILTER_CONF} > $TMP && \
        mv $TMP ${IPFILTER_CONF} && \
        ${IPFILTER_PATH} -Fa && \
        ${IPFILTER_PATH} -f ${IPFILTER_CONF}
}

fw_release() {
    if test $SSHG_ADDRKIND != 4; then
        return 1
    fi
    TMP=`mktemp /tmp/ipfconf.XXXXX`
    awk 'BEGIN { copy = 1 } copy ; /^##sshguard-begin##$/    { copy = 0 ; next } !copy { if ($0 !~ /'\"$SSHG_ADDR\"'.* /) print $0 } /^##sshguard-end##$/  { copy = 1 }' < ${IPFILTER_CONF} >$TMP && \
        mv $TMP ${IPFILTER_CONF} && \
        ${IPFILTER_PATH} -Fa && \
        ${IPFILTER_PATH} -f ${IPFILTER_CONF}
}

fw_flush() {
    TMP=`mktemp /tmp/ipfconf.XXXXX`
    awk 'BEGIN { copy = 1 } /^##sshguard-begin##$/ { print $0 ; copy = 0 } /^##sshguard-end##$/ { copy = 1 } copy' <${IPFILTER_CONF} >$TMP && \
        mv $TMP ${IPFILTER_CONF} && \
        ${IPFILTER_PATH} -Fa && \
        ${IPFILTER_PATH} -f ${IPFILTER_CONF}
}

fw_fin() {
    :
}
