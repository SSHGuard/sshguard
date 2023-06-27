#pragma once

#include "config.h"

#if defined(CAPSICUM)
#define WITH_CASPER
#include <sys/nv.h>
#include <libcasper.h>
#include <casper/cap_net.h>

extern cap_channel_t *capcas, *capnet;

#define getaddrinfo(name, serv, hints, res) cap_getaddrinfo(capnet, name, serv, hints, res)
#endif

void sandbox_init();
