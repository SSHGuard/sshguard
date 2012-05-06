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

==============
 **sshguard**
==============

------------------------
monitors daemon activity
------------------------

:Date: Mar 31, 2010
:Manual section: 8
:Version: 1.5
:Manual group: BSD System Manager's Manual

SYNOPSIS
========

| **sshguard** [-b thr:filename] [-v] [-l source] [-a sAfety_thresh] [-p pardon_min_interval]
|              [-s preScribe_interval] [-w addr/host/block/file] [-f srv:pidfile]

DESCRIPTION
===========
**sshguard** monitors logging activity and reacts to attacks by blocking their
source addresses.

**sshguard** was born for protecting SSH servers from the today's widespread
brute force attacks, and evolved to an extensible log supervisor for blocking
attacks to applications in real-time.

**sshguard** can monitor a number of log sources proactively, or receive log
messages in its standard input. By means of a parser, it decides whether an
entry is normal activity or attack; in the latter case, it remarks the
attacker's address. When sshguard determines that an attacker committed enough
danger to the system to discern an abuse, it blocks the attacker's address with
the firewall. The attacker becomes offender, and is released after an adequate
period of time.

**sshguard** supports the following firewalls:

AIX native firewall
  for IBM AIX operating systems

netfilter/iptables
  for Linux-based operating systems

Packet Filter (PF)
  for BSD operating systems (Open, Free, Net, DragonFly -BSD)

IPFirewall (IPFW)
  for FreeBSD and Mac OS X

IP Filter (IPFILTER)
  for FreeBSD, NetBSD and Solaris

tcpd's hosts_access (/etc/hosts.allow)
  portable across UNIX

null
  portable do-nothing backend for running detection without prevention

Some terms in this manual have a special meaning in the context. **sshguard**
refers to them consistently throughout documentation, source code, and log
messages. See http://www.sshguard.net/docs/terminology/ to get acquainted with
them.

USAGE
=====
**sshguard** reads log entries to analyze by monitoring a number of log sources.
It can interpret logs with all of the following formats:

* syslog
* syslog-ng
* metalog
* multilog
* raw messages

**sshguard** can interface with the following blocking systems to block
attackers:

* IBM AIX firewall
* PF
* netfilter/iptables
* IPFW
* IP Filter
* /etc/hosts.allow
* null firewall

Depending on the way chosen for giving logs to **sshguard**, and depending on the
chosen blocking system, some setup may be needed. Instructions are documented at
http://www.sshguard.net/docs/setup/.

**sshguard** does not make use of any configuration file. Instead, a combination
of optional arguments can be passed to its process on the command line, for
modifying its default behaviour:

-a sAfety_thresh
                block an attacker after it incurred a total dangerousness
                exceeding sAfety_thresh. Most attacks incur dangerousness 10.
                See http://www.sshguard.net/docs/reference/attack-signatures/
                for details. (Default: 40)

-b [thresh:]filename
                enable blacklisting: blacklist after thresh (or 120)
                dangerousness committed, and hold the permanent blacklist in
                filename.  See TOUCHINESS & BLACKLISTING below.


-e filename     execute extra external program filename whenever an event is
                triggered. See EXTERNAL PROGRAMS below.

-v              print summary information on **sshguard** and exit.

-i pidfile      store my PID in file pidfile at startup (for control scripts).

-l source       enable the Log Sucker, and add source to the list of log sources
                to monitor. source is a filename, a FIFO name, or the magic
                symbol "-" to identify **sshguard**'s standard input. **sshguard**
                handles autonomously file-like sources disappearing,
                reappearing, or "rotating". This option can be used multiple
                times. When omitted, source defaults to standard input.
                Otherwise, standard input is ignored unless explicitly added.


-p secs         release a blocked address no sooner than secs seconds after
                being blocked for the first time. **sshguard** will release the
                address between X and 3/2 * X seconds after blocking it.
                (Default: 7*60)

-s secs         forget about an address after secs seconds. If host A issues one
                attack every this many seconds, it will never be blocked.
                (Default: 20*60)

-w addr/host/block/file
                see the WHITELISTING section.

-f servicecode:pidfile
                see the LOG VALIDATION section.

When **sshguard** is signalled with SIGTSTP, it suspends activity. When **sshguard**
is signalled with SIGCONT, it resumes monitoring. During suspension, log entries
are discarded without being analyzed.

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

EXTENSIONS
==========
**sshguard** operates firewalls through a general interface, which enables easy
extension, and allows back-ends to be non-local (e.g. remote appliances), and
non-blocking (e.g. report tools). Additions can be suggested at
http://www.sshguard.net/feedback/firewall/submit/.

Extending attack signatures needs some expertise with context-free parsers;
users are welcome to submit samples of the desired log messages to
http://www.sshguard.net/support/attacks/submit/.

SEE ALSO
========
syslog(1), syslog.conf(5)

**sshguard** website at: http://www.sshguard.net/
