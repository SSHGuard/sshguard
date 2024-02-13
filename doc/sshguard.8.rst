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

:Date: March 16, 2021
:Manual group: SSHGuard Manual
:Manual section: 8
:Version: 2.4

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

**sshguard** can monitor log files and the standard output of running a shell
command. Log messages are parsed line-by-line for recognized attack patterns.
Attackers are blocked when enough attack patterns are detected in a
configurable time interval. Attackers are blocked temporarily but can also be
permanently blocked using the blacklist option.

**sshguard** must be configured before its first run. See
**sshguard-setup(7)**.

OPTIONS
=======
**-a** *threshold* (default 30)
    Each detected attack increases an attacker's attack score, usually by 10.
    Block attackers when their attack score exceeds *threshold*.

**-b** *threshold*:*blacklist_file*
    Blacklist an attacker when its attack score exceeds *threshold*.
    Blacklisted addresses are written to *blacklist-file* and never unblocked,
    even after restarting **sshguard**.

**-i** *pidfile*
    Write the PID of **sshguard** to *pidfile*. *pidfile* is removed when
    **sshguard** exits.

**-p** *blocktime* (default 120)
    Block first-time attackers for *blocktime* seconds. Subsequent blocks
    increase in duration by a factor of 2. Since **sshguard** unblocks
    attackers at random intervals, actual block times may be somewhat longer.

**-s** *detection_time* (default 1800)
    Reset an attacker's attack score after *detection_time* seconds since the
    last attack. This means that attackers who attack every *detection_time*
    seconds are never blocked by **sshguard**. However, an increased
    *detection_time* may have an impact on legitimate users.

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
    Set to enable verbose output from **sshg-blocker**.

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
