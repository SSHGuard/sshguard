# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.60])
AC_INIT([sshguard], [2.0.0], [sshguard-users@lists.sourceforge.net])
AC_CONFIG_SRCDIR([src/sshguard.in])
AM_CONFIG_HEADER([src/common/config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

# Enable POSIX extensions on hosts that normally disable them.
AC_USE_SYSTEM_EXTENSIONS

AS_BOX([Program Checks])
AC_PROG_CC_C99
AC_PROG_RANLIB
AC_PROG_YACC
AM_PROG_AR
AM_PROG_LEX

AS_BOX([Headers, Types, and Compiler Checks])
AC_CHECK_HEADERS([getopt.h])

AC_CHECK_HEADERS([sys/capsicum.h sys/capability.h], capsicum_found=candidate)
AS_IF([test "$capsicum_found" == "candidate"],
      AC_CHECK_FUNCS([cap_enter cap_rights_limit], capsicum_found=yes))
AS_IF([test "$capsicum_found" == "yes"],
      [AC_DEFINE([CAPSICUM], [1], [Use Capsicum])])

AC_CHECK_PROGS(RST2MAN_PROG, [rst2man rst2man.py], no)
AS_IF([test "$RST2MAN_PROG" == "no"],
      [AC_MSG_ERROR([required program 'rst2man' not found.])])

AS_BOX([Library Functions])
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([socket], [socket])

AC_OUTPUT([Makefile src/Makefile src/blocker/Makefile src/fw/Makefile src/parser/Makefile])
