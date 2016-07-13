libexec_SCRIPTS = fw/sshg-fw
EXTRA_DIST = fw/ipfw.sh fw/iptables.sh fw/null.sh fw/pf.sh

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
