noinst_LIBRARIES = libfwall.a

noinst_HEADERS = \
	command_aix.h \
	command_ipfilter.h \
	command_ipfw.h \
	command_iptables.h \
	command_null.h \
	command_pf.h

if FWALL_HOSTS
libfwall_a_SOURCES = hosts.c
else
# FWALL_AIX, FWALL_IPFILTER, FWALL_IPTABLES, FWALL_PF, FWALL_NULL
libfwall_a_SOURCES = command.c
endif
