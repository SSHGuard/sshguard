=================
How to Contribute
=================

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


For Committers
==============

Commit Guidelines
-----------------
This project has a strong preference for fast-forward commits. Where
possible, merge pull requests and branches by rebasing on top of master and
fast-forwarding (without a separate merge commit). It's a holdover from when
the Subversion repository was being updated from Git and may need to be
revisited in the future, but has its benefits of linear history and
consistency with what we've done.

We like descriptive commit messages.

For big changes, feel free to use topic branches in the SSHGuard repository.
After review, they go in by rebasing master. Topic branches are usually
deleted after merging. Force pushes are welcome in topic branches but not
allowed in master.

Release Checklist
-----------------
Before release, make sure that:

- Building and installing work from source tarball: ``make distcheck``
- Change log and documentation are up-to-date
- Version number is consistent in *configure.ac* and man pages

Then:

1. Tag release: ``git tag -s -m "Tag <version> release" v<version>``
#. Build source tarball: ``make dist``
#. Sign source tarball ``./distsign <tarball>``
#. Push tags: ``git push --tags``
#. Upload release files to SourceForge.
#. Send release announcement to mailing lists.
#. Announce release on website.
