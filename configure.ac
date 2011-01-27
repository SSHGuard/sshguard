#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(sshguard, 1.5, mij@sshguard.net)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/simclist.c])
AM_CONFIG_HEADER([src/config.h])
# test if we are on Solaris, which requires outstanding practices
AC_CANONICAL_BUILD
AS_CASE([$build_os], 
        [solaris*], [on_solaris=yes])
AM_CONDITIONAL([SOLARIS], [test x$on_solaris != x])




# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_YACC
# for some command backends, as OSes like Solaris have odd default implementations
AC_PROG_EGREP
AC_PROG_AWK

AM_PROG_LEX

# Checks for libraries.
AC_CHECK_LIB(pthread, pthread_create)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h malloc.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h unistd.h getopt.h])
# Sun Studio?
AC_CHECK_DECL([__SUNPRO_C], [SUNCC="yes"], [SUNCC="no"])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([gethostbyname inet_ntoa strerror strstr strtol kqueue])
# Solaris provides these functions in separate libraries
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([gethostbyname], [nsl])

# --enable-debug
AC_ARG_ENABLE([debug],
              [  --enable-debug          Turn on debugging],
              [case "${enableval}" in
                   yes) debug=true ;;
                   no)  debug=false ;;
                   *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
               esac],
               [debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])


#   --with-firewall     for setting what blocking backend to use
AC_ARG_WITH(firewall,
[  --with-firewall=< pf | ipfw | iptables | ipfilter | hosts | aix | null >
                          Select the firewall backend],
[
 FWALLSDIR="src/fwalls"
 case "$withval" in
     aix)
        cp $FWALLSDIR/command_aix.h $FWALLSDIR/command.h
        useaix=true
        AC_CHECK_PROG(genfiltpath, genfilt, `which genfilt | xargs dirname`, "")
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
        AC_CHECK_PROG(ipfpath, ipf, `which ipf | xargs dirname`, "")
        if test x$ipfpath = x
        then
            # if ipf is not in PATH not, use "/sbin" as default path
            ipfpath=/sbin
            AC_MSG_WARN([ipf program not in path! Using /sbin as default unless --with-ipf specified])
        fi
        ;;
     ipfw)
        useipfw=true
        # is ipfw in PATH ?
        AC_CHECK_PROG(ipfwpath, ipfw, `which ipfw | xargs dirname`, "")
        if test x$ipfwpath = x
        then
            # if ipfw is not in PATH not, use "/sbin" as default path
            ipfwpath=/sbin
            AC_MSG_WARN([ipfw program not in path! Using /sbin as default unless --with-ipfw specified])
        fi
        # test whether we have ip6fw, otherwise ipfw will be used for IPv6
        AC_CHECK_PROG(hasip6fw, ip6fw, "true", "")
        if test x$hasip6fw = x
        then
            AC_MSG_NOTICE([ip6fw program not found. Assuming ipfw supports IPv6 rules on its own.])
        else
            AC_MSG_NOTICE([ip6fw found. Using ip6fw for blocking IPv6 addresses.])
            # define FWALL_HAS_IP6FW in config.h
            AC_DEFINE(FWALL_HAS_IP6FW, 1, [use ip6fw as ipfw can't take IPv6 addresses])
        fi
        ;;
     iptables)
        cp $FWALLSDIR/command_iptables.h $FWALLSDIR/command.h
        useiptables=true
        # is iptables in PATH ?
        AC_CHECK_PROG(iptablespath, iptables, `which iptables | xargs dirname`, "")
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
        AC_CHECK_PROG(pfctlpath, pfctl, `which pfctl | xargs dirname`, "")
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
        echo "Choose a valid firewall backend (see --help)"
        exit 1
        ;;
    esac
],
[
 echo "Error: please choose a valid firewall backend (see --help)" && exit 1
])
# set what firewall backend has been used, for automake
# AIX chosen
AM_CONDITIONAL(FWALL_AIX, test x$useaix = xtrue)
# HOSTS chosen
AM_CONDITIONAL(FWALL_HOSTS, test x$usehosts = xtrue)
# IPF chosen
AM_CONDITIONAL(FWALL_IPFILTER, test x$useipfilter = xtrue)
# IPFW chosen
AM_CONDITIONAL(FWALL_IPFW, test x$useipfw = xtrue)
AM_CONDITIONAL(FWALL_HAS_IP6FW, test x$hasip6fw = xtrue)
# IPTABLES chosen
AM_CONDITIONAL(FWALL_IPTABLES, test x$useiptables = xtrue)
# PF chosen
AM_CONDITIONAL(FWALL_PF, test x$usepf = xtrue)
# NULL chosen
AM_CONDITIONAL(FWALL_NULL, test x$usenull = xtrue)


##          CUSTOM SETTINGS FOR PATHS

#   --with-genfilt          for setting genfilt path
AC_ARG_WITH(genfilt,
[  --with-genfilt=path Specify the full path of the genfilt command
                               (Default: autodetect from PATH)],
[
  if test x$useaix != xtrue ; then
     AC_MSG_ERROR([Can not define genfilt path in this context, as AIX has not
                   been chosen as firewall backend])
  else
      genfiltpath=`dirname $withval`
  fi
])

#   --with-ipf              for setting ipf path
AC_ARG_WITH(ipf,
[  --with-ipf=path    Specify the full path of the ipf command
                               (Default: autodetect from PATH)],
[ 
  if test x$useipfilter != xtrue ; then
     AC_MSG_ERROR([Can not define define ipf path in this context, where iptables has not been chosen as firewall backend])
  else
     ipfpath=`dirname $withval`
  fi
])

#   --with-ipfw         for setting ipfw path
AC_ARG_WITH(ipfw,
[  --with-ipfw=path        Specify the full path for the ipfw command
                               (Default: autodetect from PATH)],
[
 if test x$useipfw != xtrue ; then
     AC_MSG_ERROR([Can not define define ipfw path in this context, where ipfw has not been chosen as firewall backend])
  else
     ipfwpath=`dirname $withval`
  fi
])

#   --with-iptables         for setting iptables path
AC_ARG_WITH(iptables,
[  --with-iptables=path    Specify the full path of the iptables command
                               (Default: autodetect from PATH)],
[ 
  if test x$useiptables != xtrue ; then
     AC_MSG_ERROR([Can not define define iptables path in this context, where iptables has not been chosen as firewall backend])
  else
     iptablespath=`dirname $withval`
  fi
])

#   --with-pfctl        for setting pfctl path
AC_ARG_WITH(pfctl,
[  --with-pfctl=path       Specify the full path for the pfctl command
                               (Default: autodetect from PATH)],
[
 if test x$usepf != xtrue ; then
     AC_MSG_ERROR([Can not define define pfctl path in this context, where PF has not been chosen as firewall backend])
  else
     pfctlpath=`dirname $withval`
  fi
])

         
##          FURTHER OPTIONS

#   --with-ipfw-range       for setting the boundaries to IPFW block rules IDs
AC_ARG_WITH(ipfw-rules-range,
[  --with-ipfw-rules-range=MIN-MAX
                          Specify the IDs range in which sshguard can put its block rules
                               (Default: "55000-55050")],
[
 if test x$useipfw != xtrue ; then
      AC_MSG_ERROR([Can not define define ipfw path in this context, where ipfw has not been chosen as firewall backend])
   else
      ipfwrange_min=`echo $withval | cut -d- -f1` 
      ipfwrange_max=`echo $withval | cut -d- -f2`
  fi
  AC_MSG_NOTICE([IPFW block rules will range between $ipfwrange_min and $ipfwrange_max])
  
  # define IPFW range in config.h
  AC_DEFINE_UNQUOTED(IPFW_RULERANGE_MIN, [$ipfwrange_min], [minimum block rule ID to use in IPFW ruleset])
  AC_DEFINE_UNQUOTED(IPFW_RULERANGE_MAX, [$ipfwrange_max], [maximum block rule ID to use in IPFW ruleset])
  ])
                            
AC_ARG_WITH(hostsfile,
[  --with-hostsfile=file
                          Specify what file to use as hosts.allow
                               (Default: /etc/hosts.allow)],
[
 if ! test -d "`dirname $withval`" ; then
     AC_MSG_ERROR([Could not access path `dirname $withval`])
  fi
  touch "$withval"
  hostsfilepath=$withval
],
[
    hostsfilepath=/etc/hosts.allow
])

#   --with-ipfilterconf     for setting IPFILTER configuration file
AC_ARG_WITH(ipfilterconf,
[  --with-ipfilterconf=file    Specify what configuration file to use for ipfilter
                                (Default: /etc/ipf.rules)],
[
  if test x$useipfilter != xtrue ; then
      AC_MSG_ERROR([Doesn't make sense to use this option if ipf has not been chosen as backend])
  else
      ipfconf=$withval
  fi
],
[
    ipfconf=/etc/ipf.rules
])
 
# define $genfiltpath in config.h
AC_DEFINE_UNQUOTED(FILT_PATH, "$genfiltpath", [path for the genfilt command])
# define $hostsfilepath in config.h
AC_DEFINE_UNQUOTED(HOSTSFILE_PATH, "$hostsfilepath", [file for /etc/hosts.allow])
# define $ipfconf as ipfilter configuration filename in config.h
AC_DEFINE_UNQUOTED(IPFILTER_CONFFILE, "$ipfconf", [filename of the ipfilter configuration file])
# define $ipfwpath in config.h
AC_DEFINE_UNQUOTED(IPFW_PATH, "$ipfwpath", [path for the ipfw command])
# define $ip6fwpath in config.h
AC_DEFINE_UNQUOTED(IP6FW_PATH, "$ip6fwpath", [path for ip6fw command, use null if non-existent FreeBSD >=7])
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

# user feedback on options
if test x$useaix = xtrue ; then
    AC_MSG_NOTICE([Using $genfiltpath as path for genfilt])
fi
if test x$usehosts = xtrue ; then
    AC_MSG_NOTICE([Using $hostsfilepath as hosts.allow file])
fi
if test x$useipfilter = xtrue ; then
    AC_MSG_NOTICE([Using $ipfpath as location for ipf. Using $ipfconf as configuration file for ipfilter])
fi
if test x$useipfw = xtrue ; then
    AC_MSG_NOTICE([Using $ipfwpath as location for ipfw])
fi
if test x$useiptables = xtrue ; then
    AC_MSG_NOTICE([Using $iptablespath as location for iptables])
fi
if test x$usepf = xtrue ; then
    AC_MSG_NOTICE([Using $pfctlpath as location for pfctl])
fi

# compiler options
if test "$SUNCC" = "yes"
then
    # sun compiler
    OPTIMIZER_CFLAGS="-xO4 -xlibmil -xdepend"
    WARNING_CFLAGS="-v"
    STD99_CFLAGS="-xc99"
else
    # other compiler (assume gcc-compatibile :( )
    OPTIMIZER_CFLAGS="-O2"
    WARNING_CFLAGS="-Wall"
    STD99_CFLAGS="-std=c99"
fi

AC_SUBST(OPTIMIZER_CFLAGS)
AC_SUBST(WARNING_CFLAGS)
AC_SUBST(STD99_CFLAGS)

AC_OUTPUT([Makefile man/Makefile src/Makefile src/parser/Makefile src/fwalls/Makefile])

