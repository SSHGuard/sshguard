===================
Developing SSHGuard
===================

.. contents::

Issue Tracker
=============

Workflow
--------
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

Releases
========

Pre-Release Checklist
---------------------
- Build and install work from ``make dist``
- Change log is up-to-date
- Documentation is up-to-date
- Version number is updated in *configure.ac* and man page

Release Process
---------------
1. Tag release commit using ``git tag -s -m "Tag <version> release" v<version>``.
#. Generate release distribution using ``make dist``.
#. Generate distribution signature using ``./distsign <tarball>``.

Publishing Release
------------------
1. Push release tags using ``git push --tags``.
#. Upload release files to SourceForge.
#. Send release announcement to mailing lists.
#. Announce release on website.
