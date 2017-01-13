libexec_PROGRAMS = sshg-fw-hosts
libexec_SCRIPTS = sshg-fw-firewalld sshg-fw-ipfilter sshg-fw-ipfw sshg-fw-ipset sshg-fw-iptables sshg-fw-null sshg-fw-pf

CLEANFILES=$(libexec_SCRIPTS)
EXTRA_DIST = sshg-fw.in *.sh

sshg_fw_hosts_SOURCES = fw.h hosts.c ../common/simclist.c

SUFFIXES=.sh
.sh:
	cat $< sshg-fw.in > $@
