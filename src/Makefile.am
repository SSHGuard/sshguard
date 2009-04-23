SUBDIRS = fwalls

AM_CFLAGS=-I. -O2 -std=c99 -Wall
AM_YFLAGS = -d
#AM_LFLAGS = -d

if DEBUG
AM_CFLAGS+= -g
endif

BUILT_SOURCES = attack_parser.h
sbin_PROGRAMS = sshguard
sshguard_SOURCES = attack_parser.y attack_scanner.l sshguard.c sshguard_whitelist.c sshguard_log.c sshguard_procauth.c sshguard_blacklist.c sshguard_options.c simclist.c
sshguard_LDADD = fwalls/libfwall.a
