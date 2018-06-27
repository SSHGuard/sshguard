=================
How to Contribute
=================

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

If there's any part of the code you'd like to dive into, post on the list and
we'll show you where to get started.

.. _issue tracker: https://bitbucket.org/sshguard/sshguard/issues?status=new&status=open

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

- Building and installing work from source tarball: ``make distcheck``
- Change log and documentation are up-to-date
- Version number is consistent in *configure.ac* and man pages

Then:

1. Tag release: ``git tag -s -m "Tag <version> release" v<version>``
#. Build source tarball: ``autoreconf -i && ./configure && make dist``
#. Sign source tarball ``./distsign <tarball>``
#. Push tags: ``git push --tags``
#. Upload release files to SourceForge.
#. Send release announcement to mailing lists.
#. Announce release on website.
