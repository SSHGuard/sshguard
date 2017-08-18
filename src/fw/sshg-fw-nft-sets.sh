#!/bin/sh
# sshg-fw-nft-sets
# This file is part of SSHGuard.

CMD_NFT=nft

NFT_TABLE=sshguard
NFT_CHAIN=blacklist
NFT_SET=attackers

proto() {
    if [ "6" = "$1" ]; then
        echo ip6
    else
	echo ip
    fi
}

run_nft() {
    ${CMD_NFT} $1 $(proto $3) "${NFT_TABLE}" "$2" > /dev/null 2>&1
}

fw_init() {
    run_nft "add table" "" 4
    run_nft "add table" "" 6

    run_nft "add chain" "${NFT_CHAIN}"' { type filter hook input priority -10 ; }' 4
    run_nft "add chain" "${NFT_CHAIN}"' { type filter hook input priority -10 ; }' 6

    # Create sets
    run_nft "add set" "${NFT_SET} { type ipv4_addr; flags interval; }" 4
    run_nft "add set" "${NFT_SET} { type ipv6_addr; flags interval; }" 6

    # Rule to drop sets' IP
    run_nft "add rule" "${NFT_CHAIN} ip saddr @${NFT_SET} drop" 4
    run_nft "add rule" "${NFT_CHAIN} ip6 saddr @${NFT_SET} drop" 6
}

fw_block() {
    run_nft "add element" "${NFT_SET} { $1/$3 }" $2
}

fw_release() {
    run_nft "delete element" "${NFT_SET} { $1/$3 }" $2
}

fw_flush() {
    fw_fin
    fw_init
}

fw_fin() {
    # Remove tables
    run_nft "delete table" "" 4
    run_nft "delete table" "" 6
}
