.. Copyright (c) 2007,2008,2009,2010 Mij <mij@sshguard.net>

.. Permission to use, copy, modify, and distribute this software for any
.. purpose with or without fee is hereby granted, provided that the above
.. copyright notice and this permission notice appear in all copies.

.. THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
.. WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
.. MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
.. ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
.. WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
.. ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
.. OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

========
sshguard
========

----------------------------------------------------
block brute-force attacks by aggregating system logs
----------------------------------------------------

:Date: April 15, 2015
:Manual group: SSHGuard Manual
:Manual section: 8
:Version: 1.6

SYNOPSIS
========
**sshguard** [**-v**]
[**-a** `thresh`]
[**-b** `thresh`:`file`]
[**-e** `script`]
[**-f** `service`:`pidfile`]
[**-i** `pidfile`]
[**-l** `source`]
[**-p** `interval`]
[**-s** `interval`]
[**-w** `address` | `file`]

DESCRIPTION
===========
**sshguard** protects hosts from brute-force attacks against SSH and other
services. It aggregates system logs and blocks repeat offenders using one of
several firewall backends, including ``iptables``, ``ipfw``, and ``pf``.

**sshguard** can read log messages from standard input (suitable for piping
from ``syslog``) or monitor one or more log files. Log messages are parsed,
line-by-line, for recognized patterns. If an attack, such as several login
failures within a few seconds, is detected, the offending IP is blocked.
Offenders are unblocked after a set interval, but can be semi-permanently
banned using the blacklist option.

For clarification on some specific terms used in the source code and
documentation, please see http://www.sshguard.net/docs/terminology/.

FEATURES
========
**sshguard** can block attackers using one of several backends:

- AIX native firewall, for IBM AIX operating systems
- netfilter/iptables, for Linux-based operating systems
- ``pf``, for several BSD operating systems
- ``ipfw``, for FreeBSD and Mac OS X
- ``ipfilter``, for FreeBSD, NetBSD and Solaris
- *hosts.allow*, which uses TCP Wrappers to block attackers
- null, which runs **sshguard** without blocking any attackers

**sshguard** understands several log formats:

* syslog(-ng)
* metalog
* multilog
* raw messages

See http://www.sshguard.net/docs/reference/attack-signatures/ for a list of
recognized attacks.

SETUP
=====
Please see http://www.sshguard.net/docs/setup/ for instructions on setting
up **sshguard** with specific log systems and backends.

OPTIONS
=======
**-a** `thresh` (default 40)
    Block an attacker when its dangerousness exceeds `thresh`. Currently,
    all recognized patterns have a dangerousness of 10.

**-b** `thresh`:`file`
    Enable blacklisting. When a repeat attacker's dangerousness exceeds
    `thresh`, add its address to the blacklist file stored in `file`. See
    TOUCHINESS & BLACKLISTING below.

**-e** `script`
    Execute an external program when an event is triggered. See EXTERNAL
    PROGRAMS below.

**-f** `service`:`pidfile`
    See LOG VALIDATION below.

**-i** `pidfile`
    Write the PID of **sshguard** to `pidfile`.

**-l** `source`
    Monitor `source` for log messages. By default, **sshguard** reads log
    messages from standard input. Give this option once for every source to
    monitor instead. **sshguard** transparently handles log rotations. When
    using this option, standard input is ignored, but can be re-added by
    giving '**-l** -'.

**-p** `interval` (default 420 secs, or 7 minutes)
    Wait at least `interval` seconds before releasing a blocked address. In
    practice it takes longer for an attacker to be unblocked, because
    **sshguard** checks only at periodic intervals.

**-s** `interval` (default 1200 secs, or 20 minutes)
    Forget about an attacker `interval` seconds after its last attempt. Its
    dangerousness will be reset to zero.

**-w** `address` | `file`
    Whitelist the given address, hostname, or address block. Alternatively,
    read whitelist entires from `file`. This option can be given multiple
    times. See WHITELISTING below for details.

**-v**
    Print version information and exit.

When **sshguard** is signalled with SIGTSTP, it suspends activity. When
**sshguard** is signalled with SIGCONT, it resumes monitoring. During
suspension, log entries are discarded without being analyzed.

ENVIRONMENT
===========
When **sshguard** senses the SSHGUARD_DEBUG environment variable, it enables
debugging mode: logging is directed to standard error instead of syslog, and
includes comprehensive details of the activity and parsing process. Debugging
mode can help investigating attack signatures: once enabled, a log message can
be directly pasted into the tool from the console, and the behavior is
immediately and minutely shown beneath.

EXTERNAL PROGRAMS
=================
**sshguard** can be instructed to execute an external program whenever an event
relevant to the firewall is triggered.

The logic and capabilities of external programs are similar to those of a
database trigger. When an event is triggered, the external program can:

* add behavior to the firewall action (e.g. custom notifications)
* change behavior of the firewall action (e.g. block different address)
* cancel the firewall action (e.g. custom whitelisting)

External programs are run on all firewall events. Every external program has
these responsibilities:

* to define the behavior associated with every event (action), and especially to
  not behave on events of disinterest.
* to run the final firewall intended firewall action (or not).
* to exit with a relevant status for success (0) or failure (non-0).

The action that the external process is called to carry out determines the
information passed to it. All information passed from **sshguard** to external
programs is via environment variables:

SSHG_ACTION
  (all actions) The name of the trigger event: one value amongst:

  * init
  * fin
  * block (*)
  * block_list (*)
  * release (*)
  * flush

SSHG_PID
  (all actions) The PID of the **sshguard** process running the program.

SSHG_FWCMD
  (all actions) The firewall command that **sshguard** intended to run if no
  extra program were given. The external program shall run this within a shell.

SSHG_ADDR
  (marked actions) The address, or the comma-separated list of addresses, to
  operate.

SSHG_ADDRKIND
  (marked actions) The type of the address(es) to operate: '4' for IPv4, '6'
  for IPv6.

SSHG_SERVICE
  (marked actions) The service target of the event, expressed as service code.
  See http://www.sshguard.net/docs/reference/service-codes/.

WHITELISTING
============
**sshguard** supports address whitelisting. Whitelisted addresses are not
blocked even if they appear to generate attacks. This is useful for protecting
lame LAN users (or external friendly users) from being incidentally blocked.

Whitelist addresses are controlled through the -w command-line option. This
option can add explicit addresses, host names and address blocks:

addresses
  specify the numeric IPv4 or IPv6 address directly, like::

        -w 192.168.1.10

  or in multiple occurrences::

        -w 192.168.1.10 -w 2001:0db8:85a3:0000:0000:8a2e:0370:7334

host names
  specify the host name directly, like::

        -w friendhost.enterprise.com

  or in multiple occurrences::

        -w friendhost.enterprise.com -w friend2.enterprise.com

  All IPv4 and IPv6 addresses that the host resolves to are whitelisted. Hosts
  are resolved to addresses once, when **sshguard** starts up.

address blocks
  specify the IPv4 or IPv6 address block in the usual CIDR notation::

        -w 2002:836b:4179::836b:0000/126

  or in multiple occurrences::

        -w 192.168.0.0/24 -w 1.2.3.128/26

file
  When longer lists are needed for whitelisting, they can be wrapped into a
  plain text file, one address/hostname/block per line, with the same syntax
  given above.

  **sshguard** can take whitelists from files when the -w option argument begins
  with a '.' (dot) or '/' (slash).

  This is a sample whitelist file (say /etc/friends)::

      # comment line (a '#' as very first character)
      #   a single IPv4 and IPv6 address
      1.2.3.4
      2001:0db8:85a3:08d3:1319:8a2e:0370:7344
      #   address blocks in CIDR notation
      127.0.0.0/8
      10.11.128.0/17
      192.168.0.0/24
      2002:836b:4179::836b:0000/126
      #   hostnames
      rome-fw.enterprise.com
      hosts.friends.com

  And this is how **sshguard** is told to make a whitelist up from the
  /etc/friends file::

        sshguard -w /etc/friends

The -w option can be used only once for files. For addresses, host names and
address blocks it can be used with any multiplicity, even with mixes of them.

LOG VALIDATION
==============
Syslog and syslog-ng typically insert a PID of the generating process in every
log message. This can be checked for authenticating the source of the message
and avoid false attacks to be detected because malicious local users inject
crafted log messages. This way **sshguard** can be safely used even on hosts
where this assumption does not hold.

Log validation is only needed when **sshguard** is fed log messages from syslog
or from syslog-ng. When a process logs directly to a raw file and sshguard is
configured for polling logs directly from it, you only need to adjust the log
file permissions so that only root can write on it.

For enabling log validation on a given service the -f option is used as
follows::

      -f 100:/var/run/sshd.pid

which associates the given pidfile to the ssh service (code 100). A list of
well-known service codes is available at
http://www.sshguard.net/docs/reference/service-codes/.

The -f option can be used multiple times for associating different services with
their pidfile::

      sshguard -f 100:/var/run/sshd.pid -f 123:/var/run/mydaemon.pid

Services that are not configured for log validation follow a default-allow
policy (all of their log messages are accepted by default).

PIDs are checked with the following policy:

1. the logging service is searched in the list of services configured for
   validation. If not found, the entry is accepted.
2. the logged PID is compared with the pidfile. If it matches, the entry is
   accepted
3. the PID is checked for being a direct child of the authoritative process. If
   it is, the entry is accepted.
4. the entry is ignored.

Low I/O load is committed to the operating system because of an internal caching
mechanism. Changes in the pidfile value are handled transparently.

TOUCHINESS & BLACKLISTING
=========================
In many cases, attacks against services are performed in bulk in an automated
form. For example, the attacker goes trough a dictionary of 1500
username/password pairs and sequentially tries to violate the SSH service with
any of them, continuing blindly while blocked, and re-appearing once the block
expires.

To counteract these cases, **sshguard** by default behaves with touchiness.
Besides observing abuses from the log activity, it also monitors the overall
behavior of attackers. The decision on when and how to block is thus made
respective to the entire history of the offender as well. For example, if
address A attacks repeatedly and the base blocking time is 420 seconds, A will
be blocked for 420 seconds (7 mins) at the first abuse, 2*420 (14 mins) the
second, 2*2*420 (28 mins) the third .\.\. and 2^(n-1)*420 the n-th time.

Touchiness has two major benefits: to legitimate users, it grants forgiving
blockings on failed logins; to real attackers, it effectively renders large
scale attacks infeasible, because the time to perform one explodes with the
number of attempts.

Touchiness can be augmented with blacklisting (-b). With this option, after a
certain total danger committed, the address is added to a list of offenders to
be blocked permanently. The list is intended to be loaded at each startup, and
maintained/extended with new entries during operation. **sshguard** inserts a
new address after it exceeded a threshold of danger committed over recorded
history. This threshold is configurable within the -b option argument.
Blacklisted addresses are never scheduled for releasing.

The -b command line option enables blacklisting and requires the filename to use
for permanent storage of the blacklist. Optionally, a custom blacklist
threshold can be prefixed to this path, separated by ':'. For example,

::

    -b 50:/var/db/sshguard/blacklist.db

requires to blacklist addresses after having committed attacks for danger 50
(default per-attack danger is 10), and store the blacklist in file
/var/db/sshguard/blacklist.db. Although the blacklist file is not meant to be
in human-readable format, the strings(1) command can be used to peek in it for
listing the blacklisted addresses.

CONTRIBUTING
============
**sshguard** operates firewalls through a general interface, which enables easy
extension, and allows back-ends to be non-local (e.g. remote appliances), and
non-blocking (e.g. report tools). Additions can be suggested at
http://www.sshguard.net/feedback/firewall/submit/.

Extending attack signatures needs some expertise with context-free parsers;
users are welcome to submit samples of the desired log messages to
http://www.sshguard.net/support/attacks/submit/.

HISTORY
=======
**sshguard** was originally written by Michele Mazzucchi <mij@bitchx.it>.

SEE ALSO
========
syslog(1), syslog.conf(5), hosts_access(5)

<http://www.sshguard.net/>
