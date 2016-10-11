=======
Changes
=======

All notable changes to this project will be documented in this file.

*Note on deprecation:* Deprecated features will be removed in the next
non-bugfix release. If you would like to nominate a feature to be
un-deprecated, contact the project mailing list.

.. contents::

1.7.1
=====
October 2016

**Added**

- Add sample Mac OS X 10.12 style launchd.plist

**Changed**

- Allow multiple forward slashes in process name
- Log released addresses only when debugging

**Deprecated**

- Process validation (``-f`` option) is deprecated

**Fixed**

- Adjust TIMESTAMP_ISO8601 for Mac OS X 10.12
- Fix build error in hosts backend
- Fix empty functions in firewall scripts causing errors with Bash
- Flush stdout after every line in sshg-parser

1.7.0
=====
August 2016

**Added**

- Add *sshg-logtail*
- Add *sshg-parser*
- Control firewall using *sshg-fw*
- Match "no matching key exchange method" for SSH

**Deprecated**

- Hosts backend is deprecated
- Logsuck (``-l`` option) is deprecated, use *sshg-logtail* instead
- Process validation (``-f`` option) is deprecated

**Removed**

- Remove external hooks (``-e`` option)
- Remove support for genfilt and ipfilter backends

**Fixed**

- Accept socklog messages without a timestamp
- Fix excessive logging causing endless looping in logsuck
- Fix undefined assignment of initial inode number

1.6.4
=====
April 2016

- Match Postfix pre-authentication disconnects
- Fix bashisms in iptables backend
- Fix size argument in inet_ntop() call
- Remove excessive logging when polling from files
- Keep looking for unreadable files while polling
- Update Dovecot signature for POP3
- Match "Connection reset" message for SSH
- Resurrect PID file option by popular demand
- Adjust default abuse threshold

1.6.3
=====
January 2016

- Add sample systemd(8) unit file
- Disable blacklisting by default
- Fix `pfctl` command syntax with OpenBSD 5.8
- Implement logging as wrappers around syslog(2)
- Improve log and error messages
- Match sendmail authentication failures
- Remove PID file option
- Remove SIGTSTP and SIGCONT handler
- Remove reverse mapping attack signature
- Remove safe_fgets() and exit on interrupt
- Terminate state entries for hosts blocked with pf
- Update and shorten command-line usage
- Use 'configure' to set feature-test macros

1.6.2
=====
October 2015

- Make '-w' option backwards-compatible for iptables (James Harris)
- Remove support for ip6fw and 'ipfw-range' option
- Rewrite ipfw backend using command framework

1.6.1
=====
July 2015

- Accept "Received disconnect" with optional prefix
- Add support for socklog entries
- Fix 'ipfw-rules-range' option in configure script
- Fix build for 'ipfw' and 'hosts' backends
- Fix integer comparisons of different types
- Match attacks when syslog debugging is enabled

1.6.0
=====
May 2015

- Add rules for Postfix SASL login attempts
- Add support for ISO 8601 timestamps (David Caldwell)
- Add support for external commands run on firewall events (-e)
- Blacklist file is now human-readable (Armando Miraglia)
- Check tcpwrapper file permissions regardless of local umask
- Detect additional pre-auth disconnects
- Fix ipfw crash when loading an empty blacklist (Jin Choi)
- Fix log parsing on days beginning with zero
- Fix log polling on filesystems with many files (Johann H. Hauschild)
- Fix matching for Cyrus IMAP login via SASL
- Fix syslog format detection on hosts with undefined hostname
- Match SSH login failures with "via" suffix
- Remove broken kqueue(2) support
- Tweak option names and help strings
- Update SSH "Bad protocol" signature
- Use case-insensitive "invalid user" signature
- Wait for xtables lock when using iptables command (James Harris)

1.5
===
Feb 2011

- logsucker: sshguard polls multiple log files at once
- recognize syslog's "last message repeated N times" contextually and per-source
- attackers now gauged with attack *dangerousness* instead of count (adjust your -a !)
- improve IPv6 support
- add detection for: Exim, vsftpd, Sendmail, Cucipop
- improve Solaris support (thanks OpenCSW.org folks)
- handle huge blacklists efficiently
- improve logging granularity and descriptiveness
- add -i command line option for saving PID file as an aid for startup scripts
- update some attack signatures
- many other improvements, see 1.5beta and 1.5rc changelogs for complete credits
- fix a recognition problem for multilog files
- fix log filtering on OSes with inverted priority declarations
- fix file descriptor leak if "ps" command fails to run
- fix whitelist module allowing some entries to be skipped (thanks Andrea Dal Farra)
- fix segfault from invalid free() when all DNS lookups fail
- fix assertion failure when logsucker is notified before the logging completes (thanks Colin Keith)

1.4
===
Aug 2009

- add touchiness: block repeated abusers for longer
- add blacklisting: store frequent abusers for permanent blocking
- add support for IPv6 in whitelisting (experimental)
- sshguard ignores interrupted fgets() and reloads more seldom (thanks Keven Tipping)
- debug mode now enabled with SSHGUARD_DEBUG environment variable (no "-d")
- support non-POSIX libCs that require getopt.h (thanks Nobuhiro Iwamatsu)
- import newer SimCList containing a number of fixes and improvements
- firewall backends now block all traffic from attackers by default, not per-service
- netfilter/iptables backend now verifies credentials at initialization
- parser accepts "-" and "_" chars in process names
- fix detection of some ProFTPd and pure-ftp messages
- support log formats of new versions of ProFTPd
- fix one dovecot pattern
- correctly handle abuse threshold = 1 (thanks K. Tipping)
- fix handling of IPv6 with IPFW under Mac OS X Leopard (thanks David Horn)
- fix cmdline argument BoF exploitable by local users when sshguard is setuid
- support blocking IPv6 addrs in backed "hosts.allow"
- extend hosts.allow backend to support all service types
- localhost addresses are now whitelisted a priori
- extend IPv6 pattern for matching special addresses (eg, IPv4 embedded)
- fix grammar to be insensitive to a log injection in sshd (thanks J. Oosterveen)

1.3
===
Oct 2008

- fix autoconf problem
- automatically detect when ipfw supports IPv6 (thanks David Horn)
- be sensitive to proftpd messages to auth facility, not daemon (thanks Andy Berkvam)
- add sshd pattern for "Bad protocol" and "Did not receive identif string"

1.2
===
Sep 2008

- support for Cyrus IMAP
- support for SSH "possible break-in attempt" messages
- updated support for dovecot to include logging format of new versions
- (thanks Michael Maynard) fix of IPF backend causing sshguard not to
  update /etc/ipf.rules (disallow IPv6)
- fix detection of password when sshd doesn't log anything more than PAM

1.1
===
Jul 2008 (midway releases from Jul 2007 to Jun 2008)

- support suspension
- support debug mode at runtime (-d) for helping users in problem solving
- support for metalog logging format
- fix parser bug when recognizing certain IPv6 addresses
- fix segfault when the pipe to sshguard is closed unexpectedly
- support for ipfilter as blocking backend (thanks Hellmuth Michaelis for feedback)
- support for log messages authentication
- support for AIX genfilt firewall (thanks Gabor Szittner)
- fix "hosts" backend bug not discarding temporary files
- add monitoring support for new services:

  - dovecot imap
  - UWimap imap and pop
  - FreeBSD's ftpd
  - ProFTPd
  - pure-ftpd

1.0
===
May 2007

- address whitelisting for protecting friend addressess
- support for IPv6
- support for service multiplexing (behave differently for different services)
- more powerful parsing (context-free): support multilog, autotranslate
  hostnames and easily extends to a lot of services
- new blocking backend: "hosts" for /etc/hosts.deny
- paths autodetected and adjustable from ./configure
- script for trivially generating new custom backends

0.91
====
Mar 2007

- run away from scons and use autotools as building system

0.9
===
Feb 2007

- first public release
