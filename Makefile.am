SUBDIRS = src

EXTRA_DIST = doc/ examples/ CHANGELOG.rst README.rst
man_MANS = doc/sshguard.8 doc/sshguard-setup.7

SUFFIXES=.rst
.rst:
	$(RST2MAN_PROG) $< $@
