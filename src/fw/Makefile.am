dist_libexec_SCRIPTS = sshg-fw-firewalld sshg-fw-ipfilter sshg-fw-ipfw sshg-fw-ipset sshg-fw-iptables sshg-fw-null sshg-fw-pf
libexec_PROGRAMS = sshg-fw-hosts

EXTRA_DIST = firewalld.sh ipfilter.sh ipfw.sh ipset.sh iptables.sh null.sh pf.sh

sshg_fw_hosts_SOURCES = fw.h hosts.c ../common/simclist.c

# This rule uses GMake pattern matching. Since the target is shipped in the
# distfile, only those compiling from Git need GMake.
sshg-fw-%: %.sh sshg-fw.in
	cat $*.sh sshg-fw.in > $@
