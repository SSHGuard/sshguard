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

:Date: January 9, 2017
:Manual group: SSHGuard Manual
:Manual section: 8
:Version: 2.1

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

**sshguard** can monitor log files or read log messages from standard input.
Log messages are parsed line-by-line for recognized patterns. An attack is
detected when several patterns are matched in a set time interval. Attackers
are blocked temporarily but can also be semi-permanently banned using the
blacklist option.

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
Whitelisted addresses are never blocked. Addresses can be specified on the
command line or be stored in a file.

On the command line, give the **-w** option one or more times with an IP
address, CIDR address block, or hostname as an argument. Hostnames are
resolved once at startup. If a hostname resolves to multiple addresses, all
of them are whitelisted. For example::

    sshguard -w 192.168.1.10 -w 192.168.0.0/24 -w friend.example.com
        -w 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        -w 2002:836b:4179::836b:0000/126

If the argument to **-w** begins with a forward slash ('/') or dot ('.'),
the argument is treated as the path to a whitelist file.

The whitelist file contains comments (lines beginning with '#'), addresses,
address blocks, or hostnames, one per line.

SEE ALSO
========
sshguard-setup(7)
