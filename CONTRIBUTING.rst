========================
Contributing to SSHGuard
========================

.. contents::

For Users
=========
Your feedback on how you use SSHGuard, what you like, and what annoys you,
helps us improve SSHGuard.

- Subscribe to the `users mailing list
  <https://sourceforge.net/projects/sshguard/lists/sshguard-users>`_ and
  contribute to discussions on issues you care about.

- Vote for issues on the `issue tracker`_.

- Report log messages that should or should not be identified as attacks on
  the `issue tracker`_.

- Consider maintaining a package for SSHGuard on your operating system.

.. _issue tracker: https://bitbucket.org/sshguard/sshguard/issues?status=new&status=open


For Contributors
================

Architecture
------------
SSHGuard consists of a pipeline of programs that work together, depicted in
`<doc/sshguard.dot>`_.

In this diagram, processes shown with a dashed border are sandboxed, if
sandboxing support is implemented for the OS in *sandbox_init()*. Currently,
sandboxing is only implemented on FreeBSD with Capsicum and on OpenBSD with
*pledge()*.

**sshguard** reads the configuration file and spawns a pipeline.

**sshg-logtail** monitors one or more log files, aggregates them, and pipes
their contents to the next stage.

**sshg-parser** reads its input and looks for attacks. If it finds an attack,
it reports the service, remote address, address type (IPv4 or IPv6), and score
("dangerousness") to the next stage. The format is defined in *print_attack()*
(`<src/parser/parser.c>`_). This is the only program you need to change to
`add new signatures`_.

**sshg-blocker** maintains a list of recent attackers. If there are enough
attacks from an attacker in a given time interval, it commands the firewall
backend to block the attacker's address. After a certain amount of time,
**sshg-blocker** is also responsible for unblocking an attacker, or
blacklisting if configured to do so.

**sshg-fw-*** is one of several firewall backends. It reads firewall commands
from its input and runs the appropriate system commands to do the firewall.

Add New Signatures
------------------
Files to change:

- `<src/parser/tests.txt>`_
- `<src/parser/attack_scanner.l>`_
- `<src/parser/attack_parser.y>`_

If you are adding a new service, changes are also needed in:

- `<src/common/attack.h>`_
- `<src/common/service_names.c>`_

#. Obtain several samples of the log message you want to match. Add these
   attacks, along with the expected parse result, to *tests.txt*.

#. Run ``make check``, to make sure your new tests fail.

#. Create new tokens for parts of the string you want to match at the top of
   *attack_parser.y*, where the ``%token`` lines are.

#. Add regular expressions for matching your new tokens in *attack_scanner.l*.

#. Add grammar rules for your attack in *attack_parser.y*. A good starting
   point is to look at how the existing signatures are matached from the
   ``msg_single`` rule.

#. Check that your new tests pass, and that you haven't broken existing tests.
   To help debug your rule, you can run *sshg-parser* directly with the ``-d``
   flag.

Submitting Your Patches
-----------------------
We welcome your patches through:

- Email submission in ``git format-patch`` form or as a unified diff to the
  SSHGuard Users' Mailing List <sshguard-users@lists.sourceforge.net>

- A BitBucket pull request


For Committers
==============

Commit Guidelines
-----------------
- **Merge via fast-forward and rebase**. Where possible, merge pull requests
  and branches by rebasing on top of master and fast-forwarding, without
  creating a separate merge commit. Linear history makes it possible for us to
  bisect regressions.

- **50 character subject line**, followed by a blank and more details in the
  body if needed, in the commit message.

- **Work in topic branches as needed**. For changes big or small, feel free to
  use public topic branches in the SSHGuard repository.  After review, they go
  in by rebasing master. Topic branches are usually deleted after merging.
  Force pushes are welcome in topic branches but not allowed in master.

Issue Tracker Workflow
----------------------
An explanation of workflow states that aren't self-explanatory:

Open
    Issue analyzed, fair game for someone to fix

On hold
    Issue analyzed, fix deferred (e.g. due to coming architectural changes)

Resolved
    Action taken, issue resolved

Invalid
    Not an issue (e.g. external bugs, spam)

Wontfix
    Intentional behavior or rejected feature requests

Closed
    No action taken, issue resolved (e.g. already fixed in ``master``)

Release Checklist
-----------------
Before release, make sure that:

#. Change log and documentation are up-to-date
#. Version number is consistent in *configure.ac* and man pages
#. Regenerate autotools: ``autoreconf -i``
#. Building and installing work from source tarball: ``make distcheck``

Then:

1. Tag release: ``git tag -s -m "Tag <version> release" v<version>``
#. Source tarball should have been generated from ``make distcheck`` already
#. Sign source tarball ``./distsign <tarball>``
#. Push tags: ``git push --tags``
#. Upload release files to SourceForge.
#. Send release announcement to mailing lists.
#. Announce release on website.
