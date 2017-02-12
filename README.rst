========
SSHGuard
========
**sshguard** protects hosts from brute-force attacks against SSH and other
services. It aggregates system logs and blocks repeat offenders using one of
several firewall backends.

- http://www.sshguard.net/
- http://bitbucket.org/sshguard/sshguard/


Documentation
=============
See the man pages in *doc/* and the examples in *examples/*. This
documentation can also be found online at http://www.sshguard.net/docs/.


Installation
============
See *INSTALL.rst*. Briefly, if you are building from Git::

    autoreconf -i
    ./configure
    make && make install

Otherwise::

    ./configure
    make && make install


License
=======
**sshguard** is available under the terms of the `OpenBSD license
<http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/share/misc/license.template?rev=HEAD>`_,
which is based on the ISC License. See *COPYING* for details.


Authors
=======
* Michele Mazzucchi <mij@bitchx.it>,
* T.J. Jones <tjjones03@gmail.com>,
* Kevin Zheng <kevinz5000@gmail.com>
