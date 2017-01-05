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

:Date: January 4, 2017
:Manual group: SSHGuard Manual
:Manual section: 8
:Version: 2.0.0

SYNOPSIS
========
**sshguard** [**-hv**]
[**-a** *threshold*]
[**-b** *threshold*:*blacklist_file*]
[**-i** *pidfile*]
[**-p** *blocktime*]
[**-s** *detection_time*]
[**-w** *address* | *whitelist_file*]
[*file* ...]

DESCRIPTION
===========
**sshguard** protects hosts from brute-force attacks against SSH and other
services. It aggregates system logs and blocks repeat offenders using one of
several firewall backends.

**sshguard** can read log messages from standard input (suitable for piping
from ``syslog`` or ``journalctl``) or monitor one or more log files. Log
messages are parsed, line-by-line, for recognized patterns. If an attack,
such as several login failures within a few seconds, is detected, the
offending IP is blocked. Offenders are unblocked after a set interval, but
can be semi-permanently banned using the blacklist option.

See http://www.sshguard.net/docs/setup/ for setup instructions.

OPTIONS
=======
**-a** *threshold* (default 30)
    Block attackers when their cumulative attack score exceeds *threshold*.
    Most attacks have a score of 10.

**-b** *threshold*:*blacklist_file*
    Blacklist an attacker when its score exceeds *threshold*. Blacklisted
    addresses are loaded from and added to *blacklist-file*.

**-i** *pidfile*
    Write the PID of **sshguard** to `pidfile`.

**-p** *blocktime* (default 120)
    Block attackers for initially *blocktime* seconds after exceeding
    *threshold*. Subsequent blocks increase by a factor of 1.5.

    **sshguard** unblocks attacks at random intervals, so actual block times
    will be longer.

**-s** *detection_time* (default 1800)
    Remember potential attackers for up to *detection_time* seconds before
    resetting their score.

[**-w** *address* | *whitelist_file*]
    Whitelist a single address, hostname, or address block given as
    *address*. This option can be given multiple times. Alternatively,
    provide an absolute path to a *whitelist_file* containing addresses to
    whitelist. See `WHITELISTING`_.

**-h**
    Print usage information and exit.

**-v**
    Print version information and exit.

ENVIRONMENT
===========
SSHGUARD_DEBUG
    Set to enable verbose output from sshg-blocker.

FILES
=====
%PREFIX%/etc/sshguard.conf
    See sample configuration file.

WHITELISTING
============
**sshguard** supports IP address whitelisting. Whitelisted addresses are not
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

SEE ALSO
========
http://www.sshguard.net/
