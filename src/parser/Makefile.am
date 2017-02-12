AM_CFLAGS=-I$(top_srcdir)/src/common -DSIMCLIST_NO_DUMPRESTORE
AM_YFLAGS = -d

libexec_PROGRAMS = sshg-parser

BUILT_SOURCES = attack_parser.h
EXTRA_DIST = attacks.txt test-sshg-parser
TESTS = test-sshg-parser

sshg_parser_SOURCES = \
	attack.c \
	attack_parser.y \
	attack_scanner.l \
	parser.c \
	parser.h
