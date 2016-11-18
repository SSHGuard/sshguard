AM_CFLAGS=-I. -I blocker -DSIMCLIST_NO_DUMPRESTORE -DLIBEXECDIR=\"$(libexecdir)\"
AM_YFLAGS = -d
BUILT_SOURCES = parser/attack_parser.h

dist_libexec_SCRIPTS = sshg-logtail sshg-fw-firewalld sshg-fw-ipfw sshg-fw-iptables sshg-fw-null sshg-fw-pf
libexec_PROGRAMS = sshg-blocker sshg-fw-hosts sshg-parser
sbin_SCRIPTS = sshguard

EXTRA_DIST = fw/firewalld.sh fw/ipfw.sh fw/iptables.sh fw/null.sh fw/pf.sh sshguard.in
noinst_HEADERS = sandbox.h

sshg_parser_SOURCES = \
	parser/address.h \
	parser/attack.c \
	parser/attack.h \
	parser/attack_parser.y \
	parser/attack_scanner.l \
	parser/parser.h \
	parser/sshg_parser.c

sshg_blocker_SOURCES = \
	blocker/blocklist.c \
	blocker/blocklist.h \
	blocker/fnv.h \
	blocker/fw.c \
	blocker/fw.h \
	blocker/hash_32a.c \
	blocker/simclist.c \
	blocker/simclist.h \
	blocker/sshguard.c \
	blocker/sshguard.h \
	blocker/sshguard_blacklist.c \
	blocker/sshguard_blacklist.h \
	blocker/sshguard_log.c \
	blocker/sshguard_log.h \
	blocker/sshguard_options.c \
	blocker/sshguard_options.h \
	blocker/sshguard_whitelist.c \
	blocker/sshguard_whitelist.h \
	parser/attack.c

sshg_fw_hosts_SOURCES = fw/hosts.c blocker/simclist.c

script_subst = sed \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'

sshguard: Makefile sshguard.in
	$(script_subst) $@.in > $@

# This rule uses GMake pattern matching. Since the target is shipped in the
# distfile, only those compiling from Git need GMake.
sshg-fw-%: fw/%.sh fw/sshg-fw.in
	cat fw/$*.sh fw/sshg-fw.in > $@
