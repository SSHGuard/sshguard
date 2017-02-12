SUBDIRS = src

EXTRA_DIST = doc/ examples/ CHANGELOG.rst CONTRIBUTING.rst INSTALL.rst README.rst
dist_man_MANS = doc/sshguard-setup.7 doc/sshguard.8

if BUILD_MAN
SUFFIXES=.rst
.rst:
	$(RST2MAN_PROG) $< $@
endif
