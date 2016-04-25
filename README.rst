SSHGuard
========
**sshguard** protects hosts from brute-force attacks against SSH and other
services. It aggregates system logs and blocks repeat offenders using one of
several firewall backends, including ``iptables``, ``ipfw``, and ``pf``.

**sshguard** can read log messages from standard input (suitable for piping
from ``syslog``) or monitor one or more log files. Log messages are parsed,
line-by-line, for recognized patterns. If an attack, such as several login
failures within a few seconds, is detected, the offending IP is blocked.
Offenders are unblocked after a set interval, but can be semi-permanently
banned using the blacklist option.

- http://www.sshguard.net/
- http://bitbucket.org/sshguard/sshguard/

Authors
-------
- Mij <mij@bitchx.it>
- T.J. Jones <tjjones03@gmail.com>
- Kevin Zheng <kevinz5000@gmail.com>
