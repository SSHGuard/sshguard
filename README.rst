========
SSHGuard
========
**sshguard** protects hosts from brute-force attacks against SSH and other
services. It aggregates system logs and blocks repeat offenders using one of
several firewall backends.

- Website: https://www.sshguard.net/
- Bitbucket: https://bitbucket.org/sshguard/sshguard/


Installation
============
See `<INSTALL.rst>`_ for dependencies and detailed instructions. Briefly:

If you are building from **Git**, run this first::

    autoreconf -i

Then, build it like a normal source distribution::

    ./configure
    make && make install


Usage
=====
Copy the sample configuration file `<examples/sshguard.conf.sample>`_ and
follow the setup instructions in `sshguard-setup(7)
<doc/sshguard-setup.7.rst>`_. See `sshguard(8) <doc/sshguard.8.rst>`_ for
additional options.


Contributing
============
See `<CONTRIBUTING.rst>`_ for both people who want to write code, and those
who do not.


License
=======
**sshguard** is available under the terms of the `OpenBSD license
<http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/share/misc/license.template?rev=HEAD>`_,
which is based on the ISC License. See `<COPYING>`_ for details.


Authors
=======
* Michele Mazzucchi <mij@bitchx.it>,
* T.J. Jones <tjjones03@gmail.com>,
* Kevin Zheng <kevinz5000@gmail.com>
