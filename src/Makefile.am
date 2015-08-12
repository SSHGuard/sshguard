SUBDIRS = parser fwalls

AM_CFLAGS=-I. -D_XOPEN_SOURCE=600 -DSIMCLIST_NO_DUMPRESTORE

sbin_PROGRAMS = sshguard
sshguard_SOURCES = sshguard.c seekers.c sshguard_whitelist.c sshguard_log.c sshguard_procauth.c sshguard_blacklist.c sshguard_options.c sshguard_logsuck.c simclist.c hash_32a.c
sshguard_LDADD = parser/libparser.a fwalls/libfwall.a

noinst_PROGRAMS = sshg-parser
sshg_parser_SOURCES = sshguard_log.c sshg_parser.c
sshg_parser_LDADD = parser/libparser.a
