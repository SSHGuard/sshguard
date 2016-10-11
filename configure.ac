# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.60])
AC_INIT([sshguard], [1.7.1], [sshguard-users@lists.sourceforge.net])
AC_CONFIG_SRCDIR([src/simclist.c])
AM_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

##############################################################################
# Configuration Options

AC_ARG_WITH([firewall], [AS_HELP_STRING([--with-firewall=fw],
            [Firewall backend (one of pf, ipfw, iptables, hosts, or null)])],
[
 # Substitute the correct commands into the firewall script.
 AC_SUBST_FILE([sshg_fw_subr])
 sshg_fw_subr=src/fwalls/$withval.sh

 case "$withval" in
     hosts)
        usehosts=true
        ;;
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

AC_ARG_WITH([hosts], [AS_HELP_STRING([--with-hosts=file],
            [Path to allowed hosts file (default /etc/hosts.allow)])],
            [hostsfilepath=$withval],
            [hostsfilepath=/etc/hosts.allow])

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

##############################################################################
AS_BOX([Library Functions])

AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([socket], [socket])

# set what firewall backend has been used, for automake
# HOSTS chosen
AM_CONDITIONAL(FWALL_HOSTS, test x$usehosts = xtrue)

AC_DEFINE_UNQUOTED(HOSTSFILE_PATH, "$hostsfilepath", [Path to hosts.allow])

AC_OUTPUT([Makefile src/Makefile src/fwalls/sshg-fw])
