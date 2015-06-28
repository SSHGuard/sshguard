noinst_LIBRARIES = libfwall.a
libexec_SCRIPTS = sshg-fw

EXTRA_DIST = ipfw.sh iptables.sh null.sh pf.sh

libfwall_a_SOURCES = fw.h

if FWALL_HOSTS
libfwall_a_SOURCES += hosts.c
else
libfwall_a_SOURCES += fw.c
endif
