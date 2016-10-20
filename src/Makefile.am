if !FWALL_HOSTS
libexec_SCRIPTS = fwalls/sshg-fw
endif
EXTRA_DIST = fwalls/ipfw.sh fwalls/iptables.sh fwalls/null.sh fwalls/pf.sh

AM_CFLAGS=-I. -DSIMCLIST_NO_DUMPRESTORE -DLIBEXECDIR=\"$(libexecdir)\"
AM_YFLAGS = -d

BUILT_SOURCES = parser/attack_parser.h

libexec_PROGRAMS = sshg-parser
sshg_parser_SOURCES = \
	parser/address.h \
	parser/attack.c \
	parser/attack.h \
	parser/attack_parser.y \
	parser/attack_scanner.l \
	parser/parser.h \
	parser/sshg_parser.c

dist_libexec_SCRIPTS = sshg-logtail

sbin_PROGRAMS = sshguard
sshguard_SOURCES = \
	fnv.h \
	fwalls/fw.h \
	hash_32a.c \
	parser/attack.c \
	parser/attack_parser.y \
	parser/attack_scanner.l \
	simclist.c \
	simclist.h \
	sshguard.c \
	sshguard.h \
	sshguard_blacklist.c \
	sshguard_blacklist.h \
	sshguard_log.c \
	sshguard_log.h \
	sshguard_logsuck.c \
	sshguard_logsuck.h \
	sshguard_options.c \
	sshguard_options.h \
	sshguard_procauth.c \
	sshguard_procauth.h \
	sshguard_whitelist.c \
	sshguard_whitelist.h

if FWALL_HOSTS
sshguard_SOURCES += fwalls/hosts.c
else
sshguard_SOURCES += fwalls/fw.c
endif
