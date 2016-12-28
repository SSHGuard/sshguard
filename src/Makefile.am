SUBDIRS = fw parser

AM_CFLAGS=-I common -DSIMCLIST_NO_DUMPRESTORE -DLIBEXECDIR=\"$(libexecdir)\"

dist_libexec_SCRIPTS = sshg-logtail
libexec_PROGRAMS = sshg-blocker
sbin_SCRIPTS = sshguard

EXTRA_DIST = sshguard.in
noinst_HEADERS = common/address.h common/attack.h common/sandbox.h common/simclist.h

sshg_blocker_SOURCES = \
	blocker/attack.c \
	blocker/blocklist.c \
	blocker/blocklist.h \
	blocker/fnv.h \
	blocker/hash_32a.c \
	blocker/sshguard.c \
	blocker/sshguard_blacklist.c \
	blocker/sshguard_blacklist.h \
	blocker/sshguard_log.h \
	blocker/sshguard_options.c \
	blocker/sshguard_options.h \
	blocker/sshguard_whitelist.c \
	blocker/sshguard_whitelist.h \
	common/simclist.c

script_subst = sed \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@sshguardversion[@]|$(VERSION)|g'

sshguard: Makefile sshguard.in
	$(script_subst) $@.in > $@
