#include "config.h"
#include "sandbox.h"

#if defined(CAPSICUM)
#include <capsicum_helpers.h>

cap_channel_t *capcas, *capnet;
#endif

void sandbox_init() {
#ifdef CAPSICUM
    capcas = cap_init();
    if (capcas == NULL) {
        perror("Could not contact Casper");
    }
    if (caph_enter_casper() < 0) {
        perror("Could not enter capability mode");
    }
    capnet = cap_service_open(capcas, "system.net");
    if (capnet == NULL) {
        perror("Could not open system.net service");
    }
    cap_close(capcas);
#endif
#ifdef __OpenBSD__
    if (pledge("dns stdio", NULL) != 0) {
        perror("Could not pledge");
    }
#endif
}
