libexec_SCRIPTS = fwalls/sshg-fw
EXTRA_DIST = fwalls/ipfw.sh fwalls/iptables.sh fwalls/null.sh fwalls/pf.sh

AM_CFLAGS=-I. -DSIMCLIST_NO_DUMPRESTORE -DLIBEXECDIR=\"$(libexecdir)\"
AM_YFLAGS = -d

BUILT_SOURCES = parser/attack_parser.h

noinst_HEADERS = sandbox.h

libexec_PROGRAMS = sshg-blocker sshg-parser
sshg_parser_SOURCES = \
	parser/address.h \
	parser/attack.c \
	parser/attack.h \
	parser/attack_parser.y \
	parser/attack_scanner.l \
	parser/parser.h \
	parser/sshg_parser.c

dist_libexec_SCRIPTS = sshg-logtail

sshg_blocker_SOURCES = \
	fnv.h \
	fwalls/fw.h \
	hash_32a.c \
	parser/attack.c \
	simclist.c \
	simclist.h \
	sshguard.c \
	sshguard.h \
	sshguard_blacklist.c \
	sshguard_blacklist.h \
	sshguard_log.c \
	sshguard_log.h \
	sshguard_options.c \
	sshguard_options.h \
	sshguard_whitelist.c \
	sshguard_whitelist.h

if FWALL_HOSTS
sshg_blocker_SOURCES += fwalls/hosts.c
else
sshg_blocker_SOURCES += fwalls/fw.c
endif
