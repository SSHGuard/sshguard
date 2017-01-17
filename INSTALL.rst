===================
Installing SSHGuard
===================


From a package repository
=========================

SSHGuard is available in the package repository of many libre operating
systems such as FreeBSD and Linux, and add-on repositories like
Homebrew for macOS. Lookup `sshguard` in your system's package
repository to install and receive future updates from your distribution.


Building from source
====================

Obtain the source from SSHGuard's code repository on BitBucket or an
official release tarball avaialble from <http://www.sshguard.net/>. Use
`autoreconf` (usually provided by the autoconf package in your system)
to install auxiliary files, and then proceed to build and install.

    git clone https://bitbucket.org/sshguard/sshguard.git
    cd sshguard/
    autoreconf -i
    ./configure --prefix=/usr/local
    make
    make install

