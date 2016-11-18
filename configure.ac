# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.60])
AC_INIT([sshguard], [2.0.0], [sshguard-users@lists.sourceforge.net])
AC_CONFIG_SRCDIR([src/sshguard.in])
AM_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

##############################################################################
# Configuration Options

AC_ARG_ENABLE([sandbox], [AS_HELP_STRING([--disable-sandbox],
              [Disable Capsicum sandboxing])], [], [sandbox_enable=yes])

##############################################################################
AS_BOX([Program Checks])

# Enable POSIX extensions on hosts that normally disable them.
AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC_C99
AC_PROG_RANLIB
AC_PROG_YACC
AM_PROG_AR
AM_PROG_LEX

##############################################################################
AS_BOX([Headers, Types, and Compiler Checks])

# Header Files
AC_CHECK_HEADERS([getopt.h])

AS_IF([test "$sandbox_enable" == "yes"], [
       AC_CHECK_HEADERS([sys/capsicum.h sys/capability.h],
                        capsicum_found=candidate)
       AS_IF([test "$capsicum_found" == "candidate"],
           AC_CHECK_FUNCS([cap_enter cap_rights_limit],
                          capsicum_found=yes))
       AS_IF([test "$capsicum_found" == "yes"],
             [AC_DEFINE([CAPSICUM], [1], [Use Capsicum])],
             [AC_WARN([Capsicum not found; sandboxing not available])])
])

##############################################################################
AS_BOX([Library Functions])

AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([socket], [socket])

AC_OUTPUT([Makefile src/Makefile])
