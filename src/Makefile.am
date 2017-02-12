SUBDIRS = blocker fw parser

dist_libexec_SCRIPTS = sshg-logtail
sbin_SCRIPTS = sshguard

EXTRA_DIST = sshguard.in
noinst_HEADERS = common/address.h common/attack.h common/sandbox.h common/simclist.h

CLEANFILES = sshguard

script_subst = sed \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@sshguardversion[@]|$(VERSION)|g'

sshguard: Makefile sshguard.in
	$(script_subst) $(srcdir)/$@.in > $@
