/*
 * Copyright (c) 2007,2008,2010 Mij <mij@sshguard.net>
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
 * SSHGuard. See http://www.sshguard.net
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "sshguard_log.h"


const int sshguard_log_minloglevel = LOG_NOTICE;

static int sshg_log_debugging;

static char *msgbuf = NULL;
static size_t msgbuf_len;
/* when the buffer is too little, how much bigger do we make it? (factor, 0..+oo) */
static const float msgbuf_growth_factor = 0.2;
/* if msgbuf would get bigger than this, just give up increasing (bytes) */
static const size_t msgbuf_max_length = 1024;


int sshguard_log_init(int debugmode) {
    sshg_log_debugging = debugmode;
    if (! sshg_log_debugging) openlog("sshguard", LOG_PID, LOG_AUTH);

    /*
     * Prepare the message buffer. Start with 100 bytes,
     * will increase automatically if too small.
     */
    msgbuf_len = 100;
    msgbuf = (char *)malloc(msgbuf_len);
    assert(msgbuf != NULL);
    assert(msgbuf_growth_factor > 0);

    return 0;
}

/* enable/disable debug mode */
int sshguard_log_debug(int use_debug) {
    int tmp;

    if (sshg_log_debugging == use_debug)
        return use_debug;

    if (use_debug)
        closelog();
    else
        openlog("sshguard", LOG_PID, LOG_AUTH);

    tmp = sshg_log_debugging;
    sshg_log_debugging = use_debug;
    return tmp;
}

/* finalize the given logging subsystem */
int sshguard_log_fin() {
    if (! sshg_log_debugging) closelog();
    free(msgbuf);
    return 0;
}

/* increase msgbuf_growth_factor times the capacity of the logging buffer */
static void enlarge_buffer() {
    size_t newlen = msgbuf_len + msgbuf_growth_factor * msgbuf_len;
    if (newlen > msgbuf_max_length)
        newlen = msgbuf_max_length;
    free(msgbuf);
    msgbuf_len = newlen;
    msgbuf = (char *)malloc(msgbuf_len);
    assert(msgbuf != NULL);
}

/* log one message */
int sshguard_log(int prio, char *fmt, ...) {
    va_list ap;

    /* has the logging subsystem been initialized? */
    assert(msgbuf != NULL);

    /* cut irrelevant messages when not debugging */
    if (! sshg_log_debugging ) {
        /* LOG_* are sometimes defined in uncomparable manners. Find out */
        if (LOG_EMERG > LOG_DEBUG) {
            /* right ordering */
            if (prio < sshguard_log_minloglevel)
                return 0;
        } else {
            /* opposite ordering */
            if (prio > sshguard_log_minloglevel)
                return 0;
        }
    }

    va_start(ap, fmt);
    if (sshg_log_debugging) {
        vfprintf(stderr, fmt, ap);
        fflush(stderr);
        if (fmt[strlen(fmt)-1] != '\n')
            fprintf(stderr, "\n");
        fflush(stderr);
    } else {
        /* avoid the more convenient vsyslog() for portability reasons.. */
        while (vsnprintf(msgbuf, msgbuf_len, fmt, ap) >= msgbuf_len) {
            if (msgbuf_len >= msgbuf_max_length) break;
            /* msgbuf was too small to host message, increase it by 20% and retry */
            enlarge_buffer();
            va_end(ap);
            va_start(ap, fmt);
        }
        syslog(prio, "%s", msgbuf);
    }
    va_end(ap);

    return 0;
}
