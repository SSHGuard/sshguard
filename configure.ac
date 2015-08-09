# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.59])
AC_INIT([sshguard], [1.6.0], [sshguard-users@lists.sourceforge.net])
AC_CONFIG_SRCDIR([src/simclist.c])
AM_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE

AM_SILENT_RULES([yes])

##############################################################################
# Configuration Options

AC_ARG_WITH([firewall], [AS_HELP_STRING([--with-firewall=fw],
            [Firewall backend (one of pf, ipfw, iptables, ipfilter, hosts, aix, or null)])],
[
 FWALLSDIR="src/fwalls"
 case "$withval" in
     aix)
        cp $FWALLSDIR/command_aix.h $FWALLSDIR/command.h
        useaix=true
        AC_CHECK_PROG([genfiltpath], [genfilt])
        if test x$genfiltpath = x
        then
            # genfilt not in PATH, use "/usr/sbin" as default path
            genfiltpath=/usr/sbin
            AC_MSG_WARN([genfilt program not in path! Using /usr/sbin as default unless --with-genfilt specified])
        fi
        ;;
     hosts)
        usehosts=true
        ;;
     ipfilter)
        cp $FWALLSDIR/command_ipfilter.h $FWALLSDIR/command.h
        useipfilter=true
        # is ipf in PATH?
        AC_CHECK_PROG([ipfpath], [ipf])
        if test x$ipfpath = x
        then
            # if ipf is not in PATH not, use "/sbin" as default path
            ipfpath=/sbin
            AC_MSG_WARN([ipf program not in path! Using /sbin as default unless --with-ipf specified])
        fi
        ;;
     ipfw)
        cp $FWALLSDIR/command_ipfw.h $FWALLSDIR/command.h
        useipfw=true
        # is ipfw in PATH ?
        AC_CHECK_PROG([ipfwpath], [ipfw])
        if test x$ipfwpath = x
        then
            # if ipfw is not in PATH not, use "/sbin" as default path
            ipfwpath=/sbin
            AC_MSG_WARN([ipfw program not in path! Using /sbin as default unless --with-ipfw specified])
        fi
        ;;
     iptables)
        cp $FWALLSDIR/command_iptables.h $FWALLSDIR/command.h
        useiptables=true
        # is iptables in PATH ?
        AC_CHECK_PROG([iptablespath], [iptables])
        if test x$iptablespath = x
        then
            # if iptables is not in PATH not, use "/sbin" as default path
            iptablespath=/sbin
            AC_MSG_WARN([iptables program not in path! Using /sbin as default unless --with-iptables specified])
        fi
        ;;
     pf)
        cp $FWALLSDIR/command_pf.h $FWALLSDIR/command.h
        usepf=true
        # is pfctl in PATH ?
        AC_CHECK_PROG([pfctlpath], [pfctl])
        if test x$pfctlpath = x
        then
            # if pfctl is not in PATH not, use "/sbin" as default path
            pfctlpath=/sbin
            AC_MSG_WARN([pfctl program not in path! Using /sbin as default unless --with-pfctl specified])
        fi
        ;;
     null)
        cp $FWALLSDIR/command_null.h $FWALLSDIR/command.h
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

AC_ARG_WITH([genfilt], [AS_HELP_STRING([--with-genfilt=path],
            [Path to the genfilt command (default from PATH)])],
            [genfiltpath=`dirname $withval`])

AC_ARG_WITH([hosts], [AS_HELP_STRING([--with-hosts=file],
            [Path to allowed hosts file (default /etc/hosts.allow)])],
            [hostsfilepath=$withval],
            [hostsfilepath=/etc/hosts.allow])

AC_ARG_WITH([ipf], [AS_HELP_STRING([--with-ipf=path],
            [Path to the ipf command (default from PATH)])],
            [ipfpath=`dirname $withval`])

AC_ARG_WITH([ipfconf], [AS_HELP_STRING([--with-ipfconf=file],
            [Path to ipf configuration file (default /etc/ipf.rules)])],
            [ipfconf=$withval],
            [ipfconf=/etc/ipf.rules])

AC_ARG_WITH([ipfw], [AS_HELP_STRING([--with-ipfw=path],
            [Path to the ipfw command (default from PATH)])],
            [ipfwpath=`dirname $withval`])

AC_ARG_WITH([iptables], [AS_HELP_STRING([--with-iptables=path],
            [Path to the iptables command (default from PATH)])],
            [iptablespath=`dirname $withval`])

AC_ARG_WITH([pfctl], [AS_HELP_STRING([--with-pfctl=path],
            [Path to the pfctl command (default from PATH)])],
            [pfctlpath=`dirname $withval`])

##############################################################################
AS_BOX([Program Checks])
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_EGREP
AC_PROG_RANLIB
AC_PROG_YACC
AM_PROG_LEX

##############################################################################
AS_BOX([Headers, Types, and Compiler Checks])

# Header Files
AC_HEADER_STDC
AC_CHECK_HEADERS([getopt.h])

# Types
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Compiler Characteristics
AC_C_CONST
AC_C_INLINE
AC_C_RESTRICT

# Sun Studio?
AC_CHECK_DECL([__SUNPRO_C], [SUNCC="yes"], [SUNCC="no"])

AS_IF([test "$SUNCC" = "yes"], [
    # sun compiler
    WARNING_CFLAGS="-v"
], [
    # other compiler (assume gcc-compatibile :( )
    WARNING_CFLAGS="-Wall"
])

AC_SUBST(WARNING_CFLAGS)

##############################################################################
AS_BOX([Library Functions])

AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([socket], [socket])

# set what firewall backend has been used, for automake
# AIX chosen
AM_CONDITIONAL(FWALL_AIX, test x$useaix = xtrue)
# HOSTS chosen
AM_CONDITIONAL(FWALL_HOSTS, test x$usehosts = xtrue)
# IPF chosen
AM_CONDITIONAL(FWALL_IPFILTER, test x$useipfilter = xtrue)
# IPFW chosen
AM_CONDITIONAL(FWALL_IPFW, test x$useipfw = xtrue)
# IPTABLES chosen
AM_CONDITIONAL(FWALL_IPTABLES, test x$useiptables = xtrue)
# PF chosen
AM_CONDITIONAL(FWALL_PF, test x$usepf = xtrue)
# NULL chosen
AM_CONDITIONAL(FWALL_NULL, test x$usenull = xtrue)

# define $genfiltpath in config.h
AC_DEFINE_UNQUOTED(FILT_PATH, "$genfiltpath", [path for the genfilt command])
# define $hostsfilepath in config.h
AC_DEFINE_UNQUOTED(HOSTSFILE_PATH, "$hostsfilepath", [file for /etc/hosts.allow])
# define $ipfconf as ipfilter configuration filename in config.h
AC_DEFINE_UNQUOTED(IPFILTER_CONFFILE, "$ipfconf", [filename of the ipfilter configuration file])
# define $ipfwpath in config.h
AC_DEFINE_UNQUOTED(IPFW_PATH, "$ipfwpath", [path for the ipfw command])
# define $iptablespath in config.h
AC_DEFINE_UNQUOTED(IPTABLES_PATH, "$iptablespath", [path for the iptables command])
# define $ipfpath in config.h
AC_DEFINE_UNQUOTED(IPFPATH, "$ipfpath", [path for the ipf command])
# define $pfctlpath in config.h
AC_DEFINE_UNQUOTED(PFCTL_PATH, "$pfctlpath", [path for the pfctl command])
# define a suitable "grep -E" in config.h
AC_DEFINE_UNQUOTED(EGREP, $EGREP, [path and filename for a grep tool supporting -E])
# define a suitable awk
AC_DEFINE_UNQUOTED(AWK, $AWK, [path and filename for a suitable awk tool])

AC_OUTPUT([Makefile man/Makefile src/Makefile src/parser/Makefile src/fwalls/Makefile])

