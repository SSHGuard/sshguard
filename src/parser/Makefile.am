AM_CFLAGS=-I$(top_srcdir)/src/common -DSIMCLIST_NO_DUMPRESTORE
AM_YFLAGS = -d

libexec_PROGRAMS = sshg-parser

BUILT_SOURCES = attack_parser.h

sshg_parser_SOURCES = \
	attack.c \
	attack_parser.y \
	attack_scanner.l \
	parser.c \
	parser.h
