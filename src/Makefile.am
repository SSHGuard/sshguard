SUBDIRS = parser fwalls

AM_CFLAGS=-I. -std=c99 -Wall -D_POSIX_C_SOURCE=200112L

if DEBUG
AM_CFLAGS+= -g
endif

sbin_PROGRAMS = sshguard
sshguard_SOURCES = sshguard.c seekers.c sshguard_whitelist.c sshguard_log.c sshguard_procauth.c sshguard_blacklist.c sshguard_options.c sshguard_logsuck.c simclist.c hash_32a.c
sshguard_LDADD = parser/libparser.a fwalls/libfwall.a
