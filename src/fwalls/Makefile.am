AM_CFLAGS=-I. -I.. -Wall -O2 -std=c99

noinst_LIBRARIES = libfwall.a

if FWALL_HOSTS
libfwall_a_SOURCES = hosts.c
else
if FWALL_IPFW
libfwall_a_SOURCES = ipfw.c
else
# FWALL_AIX, FWALL_IPFILTER, FWALL_IPTABLES, FWALL_PF, FWALL_NULL
libfwall_a_SOURCES = command.c
endif
endif

#if FWALL_AIX
#libfwall_a_SOURCES = command.c
#else
#if FWALL_HOSTS
#libfwall_a_SOURCES = hosts.c
#else
#if FWALL_IPFILTER
#libfwall_a_SOURCES = command.c
#else
#if FWALL_IPFW
#libfwall_a_SOURCES = ipfw.c
#else
#if FWALL_IPTABLES
#libfwall_a_SOURCES = command.c
#else
#if FWALL_PF
#libfwall_a_SOURCES = command.c
#else
#if FWALL_NULL
#libfwall_a_SOURCES = command.c
#else
#libfwall_a_SOURCES = # illegal!
#endif
#endif
#endif
#endif
#endif
#endif
