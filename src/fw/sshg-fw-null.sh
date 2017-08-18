#!/bin/sh
# sshg-fw-null
# This file is part of SSHGuard.

fw_init() {
    echo "===>>> Initializing (null) firewall"
}

fw_block() {
    echo "===>>> Blocking $1/$3 (null)"
}

fw_release() {
    echo "===>>> Releasing $1/$3 (null)"
}

fw_flush() {
    echo "===>>> Flushing blocked addresses (null)"
}

fw_fin() {
    echo "===>>> Cleaning up (null) firewall"
}
