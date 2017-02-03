SUBDIRS = src

man_MANS = doc/sshguard-setup.7 doc/sshguard.8
EXTRA_DIST = examples/ CHANGELOG.rst README.rst

SUFFIXES=.rst
.rst:
	$(RST2MAN_PROG) $< $@

doc/sshguard-setup.7: doc/sshguard-setup.7.rst
doc/sshguard.8: doc/sshguard.8.rst