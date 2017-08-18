#!/bin/sh
# sshg-fw-ipset
# This file is part of SSHGuard.

fw_init() {
    ipset -quiet create -exist sshguard4 hash:ip family inet
    ipset -quiet create -exist sshguard6 hash:ip family inet6
}

fw_block() {
    ipset -quiet add -exist sshguard$2 $1/$3
}

fw_release() {
    ipset -quiet del -exist sshguard$2 $1/$3
}

fw_flush() {
    ipset -quiet flush sshguard4
    ipset -quiet flush sshguard6
}

fw_fin() {
    :
}
