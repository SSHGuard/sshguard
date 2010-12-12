AM_CFLAGS=-I. -I.. @WARNING_CFLAGS@ @OPTIMIZER_CFLAGS@ @STD99_CFLAGS@ -D_POSIX_C_SOURCE=200112L
AM_YFLAGS = -d
#AM_LFLAGS = -d

noinst_LIBRARIES = libparser.a

BUILT_SOURCES = attack_parser.h
libparser_a_SOURCES = attack_parser.y attack_scanner.l
