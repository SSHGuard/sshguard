SUBDIRS = parser fwalls

AM_CFLAGS=-I. -O2 -std=c99 -Wall

if DEBUG
AM_CFLAGS+= -g
endif

sbin_PROGRAMS = sshguard
sshguard_SOURCES = sshguard.c sshguard_whitelist.c sshguard_log.c sshguard_procauth.c sshguard_blacklist.c sshguard_options.c simclist.c
sshguard_LDADD = parser/libparser.a fwalls/libfwall.a
