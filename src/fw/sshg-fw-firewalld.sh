#!/bin/sh
# sshg-fw-firewalld
# This file is part of SSHGuard.

FIREW_CMD="firewall-cmd --quiet"
IPSET_CMD="ipset -quiet"

fw_init() {
    ${FIREW_CMD} --permanent --new-ipset="sshguard6" --type="hash:ip" --option="family=inet6"
    ${FIREW_CMD} --permanent --add-rich-rule="rule family=ipv6 source ipset=sshguard6 drop"
    ${FIREW_CMD} --permanent --new-ipset="sshguard4" --type="hash:ip" --option="family=inet"
    ${FIREW_CMD} --permanent --add-rich-rule="rule family=ipv4 source ipset=sshguard4 drop"
    ${FIREW_CMD} --reload
}

fw_block() {
    ${FIREW_CMD} --ipset="sshguard$2" --add-entry="$1/$3"
}

fw_release() {
    ${FIREW_CMD} --ipset="sshguard$2" --remove-entry="$1/$3"
}

fw_flush() {
    ${IPSET_CMD} flush sshguard6
    ${IPSET_CMD} flush sshguard4
}

fw_fin() {
    :
}
