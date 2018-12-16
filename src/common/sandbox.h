#pragma once

#include "config.h"

#if defined(CAPSICUM)
#   if defined(HAVE_SYS_CAPSICUM_H)
#   include <sys/capsicum.h>
#   elif defined(HAVE_SYS_CAPABILITY_H)
#   include <sys/capability.h>
#   endif
#endif

static inline void sandbox_init() {
#ifdef CAPSICUM
    if (cap_enter() != 0) {
        perror("Could not enter capability mode");
    }
#endif
#ifdef __OpenBSD__
    if (pledge("dns stdio", NULL) != 0) {
        perror("Could not pledge");
    }
#endif
}
