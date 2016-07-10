AM_YFLAGS = -d

noinst_LIBRARIES = libparser.a

BUILT_SOURCES = attack_parser.h
libparser_a_SOURCES = \
	address.h \
	attack.c \
	attack.h \
	attack_parser.y \
	attack_scanner.l \
	parser.h

libexec_PROGRAMS = sshg-parser
sshg_parser_SOURCES = sshg_parser.c
sshg_parser_LDADD = libparser.a
