==============
sshguard-setup
==============

----------------------------------
setting up SSHGuard on your system
----------------------------------

:Date: August 19, 2017
:Manual group: SSHGuard Manual
:Manual section: 7
:Version: 2.1

DESCRIPTION
===========
To set up SSHGuard, write *sshguard.conf* and set up the backend, if
necessary. Configuration options are documented in the sample configuration
file. A good starting point is to copy it and make the necessary changes:

1. Set **BACKEND**. You may also need to set it up to work with SSHGuard
   (see `BACKENDS`_).

2. Set **FILES**, **LOGREADER**, or both. Alternatively, give **sshguard** a
   list of files to monitor as positional arguments on the command-line. If
   none of these are set, **sshguard** will read from standard input.

Use **FILES** to specify a space-separated list of log files to monitor.
Use **LOGREADER** to specify a shell command to run to obtain logs. Both
settings are ignored if files are given on the command-line.

Sample **LOGREADER** commands for **journalctl(1)** and macOS 10.12+ are
available in the sample configuration.

OTHER LOGS
==========

syslog-ng
---------
For **syslog-ng 2.x**, add the following lines to *syslog-ng.conf*::

    # pass only entries with auth+authpriv facilities from programs other than sshguard
    filter sshlogs { facility(auth, authpriv) and not match("sshguard"); };
    # pass to this process with this template (avoids &lt;ID&gt; prefixes)
    destination sshguardproc {
    program("/usr/local/sbin/sshguard"
    template("$DATE $FULLHOST $MESSAGE\n"));
    };
    log { source(src); filter(sshlogs); destination(sshguardproc); };

For **syslog-ng 3.x**, add the following lines to *syslog-ng.conf*::

    # enable 3.x mode
    @version:3.0

    # pass only entries with auth+authpriv facilities from programs other than sshguard
    filter f_sshguard { facility(auth, authpriv) and not program("sshguard"); };
    # pass entries built with this format
    destination sshguard {
    program("/usr/sbin/sshguard"
    template("$DATE $FULLHOST $MSGHDR$MESSAGE\n")
    );
    };
    log { source(src); filter(f_sshguard); destination(sshguard); };

After restarting **syslog-ng**, SSHGuard should start as soon as a log entry
with facility ``auth`` or ``authpriv`` arrives. If you are monitoring
services other than **sshd**, add the appropriate log facilities to
*syslog-ng.conf*.

metalog
-------
Add the following lines to *metalog.conf*::

    Stuff to protect from brute force attacks :
        # for ssh
        facility = "*"
        program = "sshd"
        # other services ...
        # log to /var/log/sshguard directory
        logdir = "/var/log/sshguard"

After restarting **metalog**, log entries will appear in
*/var/log/sshguard*.  Use *log polling* to monitor the *current* log.


BACKENDS
========
SSHGuard can block attackers using one of several firewall backends that is
selected at compile-time.

.. warning:: Read the documentation for your firewall. Make sure you fully understand each rule or command in the examples below before using them. They may need to be adjusted to suit your particular configuration.

pf
--
SSHGuard adds attackers to table *<sshguard>*. Create the table and block
attackers by adding the following lines to *pf.conf*::

    table <sshguard> persist
    block in proto tcp from <sshguard>

After reloading the **pf** configuration, you can inspect the contents of
the table using::

    # pfctl -t sshguard -T show

ipfw
----
SSHGuard creates and adds attackers to table 22. The table can be used to
block attackers in your ruleset. For example::

    # ipfw add 5000 reset ip from table\(22\) to me

You can inspect the contents of the table using::

    # ipfw table 22 list


firewalld
---------
Blocked attackers are added to two ipsets named sshguard4 and sshguard6.
The entries in the ipsets are blocked by default in the default firewall
zone. Additional firewall zones can be configured using::

    # firewall-cmd --zone=zone-name --permanent \
        --add-rich-rule="rule source ipset=sshguard4 drop"
    # firewall-cmd --zone=zone-name --permanent \
        --add-rich-rule="rule source ipset=sshguard6 drop"

You can inspect the entries in the two ipsets using::

    # firewall-cmd --permanent --info-ipset=sshguard4
    # firewall-cmd --permanent --info-ipset=sshguard6


ipset
-----
Blocked attackers are added to two ipsets named sshguard4 and sshguard6.
Nothing is blocked by default, but can used as a source for iptables
and other tools. E.g.::

    # iptables  -I INPUT -m set --match-set sshguard4 src -j DROP
    # ip6tables -I INPUT -m set --match-set sshguard6 src -j DROP


netfilter/iptables
------------------
Create a chain for SSHGuard::

    # iptables -N sshguard      # for IPv4
    # ip6tables -N sshguard     # for IPv6

Update the INPUT chain to also pass the traffic to the sshguard chain at the
very end of its processing. Specify in --dport all the ports of services
your sshguard protects. If you want to prevent attackers from doing any
traffic to the host, remove the option completely::

    # block any traffic from abusers
    iptables -A INPUT -j sshguard
    ip6tables -A INPUT -j sshguard

Or::

    # block abusers only for SSH, FTP, POP, IMAP services (use "multiport" module)
    iptables -A INPUT -m multiport -p tcp --destination-ports 21,22,110,143 -j sshguard
    ip6tables -A INPUT -m multiport -p tcp --destination-ports 21,22,110,143 -j sshguard

Verify that you have NOT a default allow rule passing all ssh traffic higher
in the chain. Verify that you have NOT a default deny rule blocking all ssh
traffic in your firewall. In either case, you already have the skill to
adjust your firewall setup.

Here is a sample ruleset that makes sense::

    iptables -N sshguard
    # block whatever SSHGuard says be bad ...
    iptables -A INPUT -j sshguard
    # enable ssh, dns, http, https
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    # and block everything else (default deny)
    iptables -P INPUT DROP

When rebooting, most systems reset the firewall configuration by default. To
preserve your configuration, you usually use the iptables-save and
iptables-restore utilities. However, each Linux variant has its own "right
way".

nftables
--------
SSHGuard creates tables with a high priority and adds attackers to a set
automatically.

You can inspect the contents of the sets using::

    # nft list set ip sshguard attackers
    # nft list set ip6 sshguard attackers

Moreover, you can display sshguard's tables with::

    # nft list table ip sshguard
    # nft list table ip6 sshguard


EXAMPLES
========
Ignore **FILES** and monitor these files instead::

    # sshguard /var/log/auth.log /var/log/maillog

SEE ALSO
========
sshguard(8)
