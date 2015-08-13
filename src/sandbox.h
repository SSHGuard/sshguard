#ifndef _SANDBOX_H
#define _SANDBOX_H

#include "config.h"

#ifdef CAPSICUM
#   ifdef HAVE_SYS_CAPSICUM_H
#   include <sys/capsicum.h>
#   endif

#   ifdef HAVE_SYS_CAPABILITY_H
#   include <sys/capability.h>
#   endif
#endif

static inline void sandbox_init() {
#ifdef CAPSICUM
    if (cap_enter() != 0) {
        perror("Could not enter capability mode");
    }
#endif
}

#endif
