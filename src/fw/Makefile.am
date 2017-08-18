AM_CFLAGS=-I$(top_srcdir)/src/common -DSIMCLIST_NO_DUMPRESTORE

EXTRA_DIST = sshg-fw.in sshg-fw-firewalld.sh sshg-fw-ipfilter.sh sshg-fw-ipfw.sh sshg-fw-ipset.sh sshg-fw-iptables.sh sshg-fw-nft-sets.sh sshg-fw-null.sh sshg-fw-pf.sh

libexec_PROGRAMS = sshg-fw-hosts
libexec_SCRIPTS = sshg-fw-firewalld \
                  sshg-fw-ipfilter  \
                  sshg-fw-ipfw      \
                  sshg-fw-ipset     \
                  sshg-fw-iptables  \
                  sshg-fw-nft-sets  \
                  sshg-fw-null      \
                  sshg-fw-pf
sshg-fw-firewalld: sshg-fw.in sshg-fw-firewalld.sh
sshg-fw-ipfilter:  sshg-fw.in sshg-fw-ipfilter.sh
sshg-fw-ipfw:      sshg-fw.in sshg-fw-ipfw.sh
sshg-fw-ipset:     sshg-fw.in sshg-fw-ipset.sh
sshg-fw-iptables:  sshg-fw.in sshg-fw-iptables.sh
sshg-fw-nft-sets:  sshg-fw.in sshg-fw-nft-sets.sh
sshg-fw-null:      sshg-fw.in sshg-fw-null.sh
Sshg-fw-pf:        sshg-fw.in sshg-fw-pf.sh


CLEANFILES=$(libexec_SCRIPTS)

sshg_fw_hosts_SOURCES = fw.h hosts.c ../common/simclist.c

SUFFIXES=.sh
.sh:
	cat $< $(srcdir)/sshg-fw.in > $@
