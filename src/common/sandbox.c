#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <grp.h> // initgroups() on Linux
#include <pwd.h>
#include "sandbox.h"

#if defined(CAPSICUM)
#include <capsicum_helpers.h>

cap_channel_t *capcas, *capnet;
#endif

void init_log() {
    int debug = (getenv("SSHGUARD_DEBUG") != NULL);
    int flags = LOG_NDELAY | LOG_PID;
    int dest = LOG_AUTH;

    if (debug) {
#ifdef LOG_PERROR
        // Some OS's (like OmniOS) don't have a LOG_PERROR flag to syslog().
        flags |= LOG_PERROR;
#endif
        dest = LOG_LOCAL6;
    } else {
        setlogmask(LOG_UPTO(LOG_INFO));
    }

    // Set local time zone and open log before entering sandbox.
    tzset();
    openlog("sshguard", flags, dest);
}

void droproot(const char *user) {
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        perror("Could not find user");
        return;
    }
    if (initgroups(user, pw->pw_gid) == -1) {
        perror("Could not initialize supplementary groups");
    }

#ifdef HAVE_SETRESGID
    if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
        perror("Could not set group");
    }
#else
    if (setregid(pw->pw_gid, pw->pw_gid) == -1) {
        perror("Could not set group");
    }
#endif

#ifdef HAVE_SETRESUID
    if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
        perror("Could not set user");
    }
#else
    if (setreuid(pw->pw_uid, pw->pw_uid) == -1) {
        perror("Could not set user");
    }
#endif

}

void sandbox_init() {
    char *user = getenv("SSHGUARD_USER");
    if (user) {
        droproot(user);
    }

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
