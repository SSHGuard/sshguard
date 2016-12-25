SUBDIRS = fw

AM_CFLAGS=-I. -I blocker -DSIMCLIST_NO_DUMPRESTORE -DLIBEXECDIR=\"$(libexecdir)\"
AM_YFLAGS = -d
BUILT_SOURCES = parser/attack_parser.h

dist_libexec_SCRIPTS = sshg-logtail
libexec_PROGRAMS = sshg-blocker sshg-parser
sbin_SCRIPTS = sshguard

EXTRA_DIST = sshguard.in
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
	blocker/hash_32a.c \
	blocker/simclist.c \
	blocker/simclist.h \
	blocker/sshguard.c \
	blocker/sshguard.h \
	blocker/sshguard_blacklist.c \
	blocker/sshguard_blacklist.h \
	blocker/sshguard_log.h \
	blocker/sshguard_options.c \
	blocker/sshguard_options.h \
	blocker/sshguard_whitelist.c \
	blocker/sshguard_whitelist.h \
	parser/attack.c

script_subst = sed \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@sshguardversion[@]|$(VERSION)|g'

sshguard: Makefile sshguard.in
	$(script_subst) $@.in > $@
