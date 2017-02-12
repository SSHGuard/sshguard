AM_CFLAGS=-I$(top_srcdir)/src/common -DSIMCLIST_NO_DUMPRESTORE

libexec_PROGRAMS = sshg-blocker

sshg_blocker_SOURCES = \
	../common/simclist.c \
	attack.c \
	blocker.c \
	blocklist.c \
	blocklist.h \
	fnv.h \
	hash_32a.c \
	sshguard_blacklist.c \
	sshguard_blacklist.h \
	sshguard_log.h \
	sshguard_options.c \
	sshguard_options.h \
	sshguard_whitelist.c \
	sshguard_whitelist.h
