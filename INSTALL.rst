===================
Installing SSHGuard
===================


From a package repository
=========================
SSHGuard is available as a package from several package repositories,
usually under the name ``sshguard``.


Building from source
====================
Obtain a source distribution from http://www.sshguard.net/. Extract the
archive and run::

    ./configure
    make && make install

Alternatively, if you are building from the source repository::

    git clone https://bitbucket.org/sshguard/sshguard.git
    cd sshguard/
    autoreconf -i
    ./configure
    make && make install

Build dependencies
------------------
- C compiler with support for the C99 standard
- lex and yacc (or compatible variant)

If you are building from the source repository, you also need:

- Autoconf/Automake
- Docutils

Debian and Ubuntu
~~~~~~~~~~~~~~~~~
::

    apt install autoconf automake byacc flex gcc python-docutils

Fedora
~~~~~~
::

    dnf install autoconf automake byacc flex gcc python-docutils

FreeBSD
~~~~~~~
::

    pkg install autotools byacc clang flex py27-docutils

macOS
~~~~~
Requires Xcode_ with command line utilities and Homebrew_.

::

    brew install autoconf automake byacc docutils flex

.. _Xcode: https://itunes.apple.com/app/xcode/id497799835
.. _Homebrew: http://brew.sh/
