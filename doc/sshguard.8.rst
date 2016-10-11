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

:Date: October 11, 2016
:Manual group: SSHGuard Manual
:Manual section: 8
:Version: 1.7.1

SYNOPSIS
========
**sshguard** [**-v**]
[**-a** `thresh`]
[**-b** `thresh`:`file`]
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

See http://www.sshguard.net/docs/setup/ for setup instructions.

Other features, attack signatures, and additional documentation can be found
at http://www.sshguard.net/.

OPTIONS
=======
**-a** `thresh` (default 30)
    Block an attacker when its dangerousness exceeds `thresh`. Each attack
    pattern that is matched contributes a fixed dangerousness of 10.

**-b** `thresh`:`file`
    Blacklist an attacker when its dangerousness exceeds `thresh`.
    Blacklisted addresses are added to `file` so they can be read at the
    next startup. Blacklisted addresses are never automatically unblocked,
    but it is good practice to periodically clean out stale blacklist
    entries.

**-f** `service`:`pidfile`
    Deprecated. See LOG VALIDATION below.

**-i** `pidfile`
    Write the PID of **sshguard** to `pidfile`.

**-l** `source`
    Monitor `source` for log messages. By default, **sshguard** reads log
    messages from standard input. Give this option once for every source to
    monitor instead. **sshguard** transparently handles log rotations. When
    using this option, standard input is ignored, but can be re-added by
    giving '**-l** -'.

**-p** `interval` (default 120 secs, or 2 minutes)
    Wait at least `interval` seconds before releasing a blocked address.
    Repeat attackers are blocked for 1.5 times longer after each attack.
    Because **sshguard** unblocks attackers only at infrequent intervals,
    this parameter is inexact (actual blocks will be longer).

**-s** `interval` (default 1800 secs, or 30 minutes)
    Forget about an attacker `interval` seconds after its last attempt. Its
    dangerousness will be reset to zero.

**-w** `address` | `file`
    Whitelist the given address, hostname, or address block. Alternatively,
    read whitelist entires from `file`. This option can be given multiple
    times. See WHITELISTING below for details.

**-v**
    Print version information and exit.

ENVIRONMENT
===========
SSHGUARD_DEBUG
    Enable additional debugging information.

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

SEE ALSO
========
syslog(1), syslog.conf(5), hosts_access(5)

Glossary: http://www.sshguard.net/docs/terminology/

Website: http://www.sshguard.net/

AUTHORS
=======
Michele Mazzucchi <mij@bitchx.it>, Kevin Zheng <kevinz5000@gmail.com>
