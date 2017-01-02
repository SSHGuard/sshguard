#!/bin/sh
# sshg-fw-firewalld
# This file is part of SSHGuard.

fw_init() {
    firewall-cmd --quiet --permanent --new-ipset="sshguard4" --type=hash:ip --option="family=inet"
    firewall-cmd --quiet --permanent --add-rich-rule="rule source ipset=sshguard4 drop"
    firewall-cmd --quiet --permanent --new-ipset="sshguard6" --type=hash:ip --option="family=inet6"
    firewall-cmd --quiet --permanent --add-rich-rule="rule source ipset=sshguard6 drop"
    firewall-cmd --quiet --reload
}

fw_block() {
    firewall-cmd --quiet --permanent --ipset="sshguard$2" --add-entry="$1"
    firewall-cmd --quiet --reload
}

fw_release() {
    firewall-cmd --quiet --permanent --ipset="sshguard$2" --remove-entry="$1"
    firewall-cmd --quiet --reload
}

fw_flush() {
    firewall-cmd --quiet --permanent --delete-ipset="sshguard4"
    firewall-cmd --quiet --permanent --new-ipset="sshguard4" --type=hash:ip --option="family=inet"
    firewall-cmd --quiet --permanent --delete-ipset="sshguard6"
    firewall-cmd --quiet --permanent --new-ipset="sshguard6" --type=hash:ip --option="family=inet6"
    firewall-cmd --quiet --reload
}

fw_fin() {
    :
}
