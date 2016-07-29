===================
Setting Up SSHGuard
===================

.. contents::


Reading system logs
===================
SSHGuard can monitor system logs by reading from a log daemon or by polling
log files.

syslog
------
**syslogd** can be configured to pipe logs to SSHGuard using *syslog.conf*::

    auth.info;authpriv.info        |exec /path/to/sshguard

After restarting **syslogd**, SSHGuard should start as soon as a log entry
with level ``auth.info`` or ``authpriv.info`` arrives. If you are monitoring
services other than **sshd**, add the appropriate log facilities to
*syslog.conf*. See *syslog.conf(5)* for more details.

.. note:: **syslogd** will terminate and restart SSHGuard when it receives *SIGHUP* from **newsyslog**, flushing any blocked addresses. This may occur several times a day, depending on how often logs are rotated on your system. If this behavior is undesirable, use *log polling* instead.

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

Log polling (Log Sucker)
------------------------
SSHGuard can poll multiple files for log entries using the ``-l`` option. It
re-opens rotated logs and handles disappearing files automatically. The
following example polls two log files::

    # sshguard -l /var/log/auth.log -l /var/log/maillog

By default, SSHGuard does not read log entries from standard input when log
polling is enabled. Add ``-l -`` to include standard input in the list of
files to poll.

.. note:: Some entries might be incorrectly discarded when using log validation combined with log polling. Avoid using both features at the same time.


Blocking attackers
==================
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

TCP Wrapper
-----------
Add the following lines to *hosts.allow*::

    ##sshguard##
    ##sshguard##

SSHGuard will add or remove rules between these two lines.
