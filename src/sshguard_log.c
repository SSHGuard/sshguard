/*
 * Copyright (c) 2007,2008 Mij <mij@bitchx.it>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * SSHGuard. See http://sshguard.sourceforge.net
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sshguard_log.h"

int sshg_log_debugging;

int sshguard_log_init(int debugmode) {
    sshg_log_debugging = debugmode;
    if (! sshg_log_debugging) openlog("sshguard", LOG_PID, LOG_AUTH);
    return 0;
}

/* finalize the given logging subsystem */
int sshguard_log_fin() {
    if (! sshg_log_debugging) closelog();
    return 0;
}

int sshguard_log(int prio, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (sshg_log_debugging) {
        vfprintf(stderr, fmt, ap);
        if (fmt[strlen(fmt)-1] != '\n') fprintf(stderr, "\n");
    } else
        vsyslog(prio, fmt, ap);
    va_end(ap);

    return 0;
}
