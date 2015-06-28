SUBDIRS = parser fwalls

AM_CFLAGS=-I. -DSIMCLIST_NO_DUMPRESTORE

sbin_PROGRAMS = sshguard
sshguard_SOURCES = \
	fnv.h \
	hash_32a.c \
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
sshguard_LDADD = parser/libparser.a fwalls/libfwall.a

noinst_PROGRAMS = sshg-parser
sshg_parser_SOURCES = sshguard_log.c sshg_parser.c
sshg_parser_LDADD = parser/libparser.a
