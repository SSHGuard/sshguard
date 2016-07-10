# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.60])
AC_INIT([sshguard], [1.7.0], [sshguard-users@lists.sourceforge.net])
AC_CONFIG_SRCDIR([src/simclist.c])
AM_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

##############################################################################
# Configuration Options

AC_ARG_ENABLE([sandbox], [AS_HELP_STRING([--disable-sandbox],
              [Disable Capsicum sandboxing])], [], [sandbox_enable=yes])

AC_ARG_WITH([firewall], [AS_HELP_STRING([--with-firewall=fw],
            [Firewall backend (one of pf, ipfw, iptables, or null)])],
[
 # Substitute the correct commands into the firewall script.
 AC_SUBST_FILE([sshg_fw_subr])
 sshg_fw_subr=src/fwalls/$withval.sh

 case "$withval" in
     ipfw)
        useipfw=true
        ;;
     iptables)
        useiptables=true
        ;;
     pf)
        usepf=true
        ;;
     null)
        usenull=true
        ;;
     *)
        AC_MSG_ERROR([Invalid firewall backend (see help)])
        ;;
    esac
],
[
AC_MSG_ERROR([Please choose a firewall backend (see help)])
])

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
       AS_IF([test "$usehosts" == "true"],
             [AC_MSG_ERROR([Hosts backend requires configuring with '--disable-sandbox'])])
       AC_CHECK_HEADERS([sys/capsicum.h sys/capability.h],
                        [capsicum_found=yes; break])
       AS_IF([test "$capsicum_found" == "yes"],
             [AC_DEFINE([CAPSICUM], [1], [Use Capsicum])],
             [AC_WARN([Capsicum not found; sandboxing not available])])
])

##############################################################################
AS_BOX([Library Functions])

AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([socket], [socket])

AC_OUTPUT([Makefile src/Makefile src/fwalls/sshg-fw])
