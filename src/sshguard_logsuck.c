/*
 * Copyright (c) 2009,2010 Mij <mij@sshguard.net>
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

#include "config.h"

#if defined(HAVE_KQUEUE)
// #define _BSD_SOURCE
#   include <sys/types.h>
#   include <sys/event.h>
#   include <sys/time.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
/* to sleep POSIX-compatibly with select() */
#include <sys/time.h>


#include "fnv.h"
#include "simclist.h"

#include "sshguard.h"
#include "sshguard_log.h"


#include "sshguard_logsuck.h"


#ifndef STDIN_FILENO
#   define STDIN_FILENO     0
#endif


/* factor of growth of the interval between polls while in idle */
#define     LOGPOLL_INTERVAL_GROWTHFACTOR     0.03

/* metainformation on a source */
typedef struct {
    char filename[PATH_MAX];            /* filename in the filesystem */
    sourceid_t source_id;               /* filename-based ID of source, constant across rotations */

    /* current situation */
    int active;                         /* is the source active? 0/1 */
    int current_descriptor;             /* current file descriptor, if active */
    int current_serial_number;          /* current serial number of the source, if active */
} source_entry_t;

/* list of source_entry_t elements */
static list_t sources_list;

#if defined(HAVE_KQUEUE)
static int kq;
/* configured or returned events. 2* because files have 2 events (read + delete/rename) */
static struct kevent kevs[2*MAX_FILES_POLLED];
/* timeout for kevent() polling */
static struct timespec kev_timeout;

/* refresh inactive files that possibly reappeared. This is cheaper than refresh_files() */
static int refresh_inactive_files();
/* sets events to be monitored. kq must be set before calling this */
static void set_kevs();
#endif


/* how many files we are actively polling (may decrease at runtime if some "disappear" */
static int num_sources_active = 0;

/* index of last file polled (used if insisting on source is required) */
static int index_last_read = -1;


/* read a line from a file descriptor into a buffer */
static int read_from(const source_entry_t *restrict source, char *restrict buf, size_t buflen);
static void deactivate_source(source_entry_t *restrict s);

/* restore (open + update) a source previously inactive, then reappeared */
static int activate_source(source_entry_t *restrict srcent, const struct stat *fileinfo);
/* test all sources (active + inactive) for changes, and refresh them if needed */
static int refresh_files();

/* meter for SimCList */
static size_t list_meter_sourceentry(const void *el) {
    return sizeof(source_entry_t);
}

#if defined(HAVE_KQUEUE)
/* seeker for file descriptors for SimCList */
static int list_seeker_filedescriptor(const void *el, const void *key) {
    const source_entry_t *elc = (const source_entry_t *)el;
    assert(el != NULL);
    assert(key != NULL);

    return elc->current_descriptor == *(int *)key;
}
#endif


int logsuck_init() {
    list_init(& sources_list);
    list_attributes_copy(& sources_list, list_meter_sourceentry, 1);

#if defined(HAVE_KQUEUE)
    /* will need file descriptor seeker to look up source items from fds */
    list_attributes_seeker(& sources_list, list_seeker_filedescriptor);
#endif

#if defined(HAVE_KQUEUE)
    /* initialize kqueue */
    if ((kq = kqueue()) == -1) {
        sshguard_log(LOG_CRIT, "Unable to create kqueue! %s.", strerror(errno));
        return -1;
    }
    /* re-test sources every this interval */
    kev_timeout.tv_sec = 1;
    kev_timeout.tv_nsec = 500 * 1000 * 1000;
#endif

    return 0;
}

int logsuck_add_logsource(const char *restrict filename) {
    source_entry_t cursource;

    assert(filename != NULL);
    if (list_size(& sources_list) >= MAX_FILES_POLLED) {
        sshguard_log(LOG_CRIT, "I can monitor at most %u files! See MAX_FILES_POLLED.", MAX_FILES_POLLED);
        return -1;
    }

    sshguard_log(LOG_DEBUG, "Adding '%s' to polled files.", filename);

    /* store filename */
    strcpy(cursource.filename, filename);

    /* compute source id (based on filename) */
    cursource.source_id = fnv_32a_str(filename, 0);

    /* open and store file descriptor */
    if (strcmp(filename, "-") == 0) {
        int fflags;
        /* read from standard input */
        cursource.current_descriptor = STDIN_FILENO;
        cursource.current_serial_number = 0;
        /* set O_NONBLOCK as the other sources (but this is already open) */
        fflags = fcntl(cursource.current_descriptor, F_GETFL, 0);
        if (fcntl(cursource.current_descriptor, F_SETFL, fflags | O_NONBLOCK) == -1) {
            sshguard_log(LOG_ERR, "Couldn't make stdin source non-blocking (%s). Bye.", strerror(errno));
            return -1;
        }
        cursource.active = 1;
        ++num_sources_active;
    } else {
        struct stat fileinfo;

        /* get current serial number */
        if (stat(filename, & fileinfo) != 0) {
            sshguard_log(LOG_ERR, "File '%s' vanished while adding!", filename);
            return -1;
        }

        if (activate_source(& cursource, & fileinfo) != 0) {
            sshguard_log(LOG_ERR, "Unable to open '%s': %s.", filename, strerror(errno));
            return -1;
        }
        /* move to the end of file */
        lseek(cursource.current_descriptor, 0, SEEK_END); /* safe to fail if file is named pipe */
    }

    /* do add */
    list_append(& sources_list, & cursource);

#if defined(HAVE_KQUEUE)
    set_kevs();
#endif

    sshguard_log(LOG_DEBUG, "File '%s' added, fd %d, serial %u.", filename, cursource.current_descriptor, cursource.current_serial_number);

    return 0;
}

int logsuck_getline(char *restrict buf, size_t buflen, bool from_previous_source, sourceid_t *restrict whichsource) {
    int ret;
#if ! defined(HAVE_KQUEUE)
    /* use active poll through non-blocking read()s */
    int sleep_interval;
    struct timeval sleepstruct;
#endif
    source_entry_t *restrict readentry;


    /* do we have to stick to the last source used? */
    if (from_previous_source && index_last_read >= 0) {
        /* get source to read from */
        readentry = (source_entry_t *restrict)list_get_at(& sources_list, index_last_read);
        if (readentry->active) {
            sshguard_log(LOG_DEBUG, "Sticking to '%s' to get next line.", readentry->filename);
            if (whichsource != NULL) *whichsource = readentry->source_id;
            return read_from(readentry, buf, buflen);
        }
        sshguard_log(LOG_ERR, "Source '%s' no longer active; can't insist reading from it.", readentry->filename);
    }

#if defined(HAVE_KQUEUE)
    /* continually wait for read events, but take breaks
     * to check for source rotations every once in a while */
    refresh_files();
    sshguard_log(LOG_DEBUG, "Start polling.");
    while (1) {
        if (num_sources_active == list_size(& sources_list)) {
            ret = kevent(kq, NULL, 0, kevs, 1, NULL);
        } else {
            ret = kevent(kq, NULL, 0, kevs, 1, & kev_timeout);
        }
        if (ret > 0) {
            if (kevs[0].filter == EVFILT_READ) {
                /* got data on this one. Read from it */
                sshguard_log(LOG_DEBUG, "Searching for fd %lu in list.", kevs[0].ident);
                readentry = list_seek(& sources_list, & kevs[0].ident);
                assert(readentry != NULL);
                assert(readentry->active);
                return read_from(readentry, buf, buflen);
            } else {
                /* some source deleted or rotated: test all sources */
                refresh_files();
            }
        } else {
            /* timeout: test only inactive sources */
            if (num_sources_active != list_size(& sources_list)) {
                refresh_inactive_files();
            }
        }
        sshguard_log(LOG_DEBUG, "Polling. Last value: %d.", ret);
    }

    sshguard_log(LOG_ERR, "Error in kevent(): %s.", strerror(errno));

#else
    /* poll all files until some stuff is read (in random order, until data is found) */
    sleep_interval = 20;
    while (1) {
        int pos, start;

        /* attempt to redeem disappeared files */
        refresh_files();

        /* pass through all files avoiding starvation */
        start = rand() % list_size(& sources_list);

        for (pos = start; pos < list_size(& sources_list) + start; ++pos) {
            index_last_read = pos % list_size(& sources_list);
            readentry = (source_entry_t *restrict)list_get_at(& sources_list, index_last_read);
            if (! readentry->active) continue;
            /* sshguard_log(LOG_DEBUG, "Attempting to read from '%s'.", readentry->filename); */
            ret = read(readentry->current_descriptor, & buf[0], 1);
            switch (ret) {
                case 1:
                    /* ignore blank lines */
                    if (buf[0] == '\n') continue;
                    /* there is stuff. Read rest of the line */
                    sshguard_log(LOG_DEBUG, "Read line from '%s'.", readentry->filename);
                    if (whichsource != NULL) *whichsource = readentry->source_id;
                    return read_from(readentry, & buf[1], buflen-1);

                case -1:
#ifdef EINTR
                    if (errno == EINTR) {
                        continue;
                    }
#endif
                    if (errno != EAGAIN) {
                        /* error */
                        sshguard_log(LOG_NOTICE, "Error while reading from file '%s': %s.", readentry->filename, strerror(errno));
                        deactivate_source(readentry);
                    }
            }
        }
        /* no data. Wait for something with exponential backoff, up to LOGSUCK_MAX_WAIT */
        sshguard_log(LOG_DEBUG, "Nothing new on any file. Wait %d millisecs for new data.", sleep_interval);
        /* sleep, POSIX-compatibly */
        sleepstruct.tv_sec = sleep_interval / 1000;
        sleepstruct.tv_usec = (sleep_interval % 1000)*1000;
        select(0, NULL, NULL, NULL, & sleepstruct);
        /* update sleep interval for next call */
        if (sleep_interval < MAX_LOGPOLL_INTERVAL) {
            sleep_interval = sleep_interval + 1+(LOGPOLL_INTERVAL_GROWTHFACTOR*sleep_interval);
            if (sleep_interval > MAX_LOGPOLL_INTERVAL)
                sleep_interval = MAX_LOGPOLL_INTERVAL;
        }
        refresh_files();
    }
#endif

    /* we shouldn't be here, or there is an error */
    return -1;
}

int logsuck_fin() {
    source_entry_t *restrict myentry;

    /* close all files and release memory for metadata */
    list_iterator_start(& sources_list);
    while (list_iterator_hasnext(& sources_list)) {
        myentry = (source_entry_t *restrict)list_iterator_next(& sources_list);

        close(myentry->current_descriptor);
    }
    list_iterator_stop(& sources_list);

    list_destroy(& sources_list);

    return 0;
}


static int read_from(const source_entry_t *restrict source, char *restrict buf, size_t buflen) {
    int i, ret, bullets;

    /* read until error, newline reached, or buffer exhausted */
    i = 0;
    bullets = 10;   /* 10 bullets for the writer to not make us wait */
    do {
        ret = read(source->current_descriptor, & buf[i++], 1);
        if (ret == 0) {
            /* if we're reading ahead of the writer, sit down wait some times */
            usleep(20 * 1000);
            --bullets;
        }
    } while (ret >= 0 && buf[i-1] != '\n' && i < buflen-2 && bullets > 0);
    buf[i] = '\0';
    if (bullets == 0) {
        /* what's up with the writer? read() patiented forever! Discard this entry. */
        sshguard_log(LOG_INFO, "Discarding partial log entry '%s': source %u cannot starve the others.", buf, source->source_id);
        buf[0] = '\0';
        return -1;
    }
    /* check result */
    if (i >= buflen) {
        sshguard_log(LOG_ERR, "Increase buffer, %ld was insufficient for '%s'.", buflen, buf);
        return -1;
    }

    return 0;
}


#if defined(HAVE_KQUEUE)
/* refresh only inactive files. When active ones change, kqueue() will notify for complete call */
static int refresh_inactive_files() {
    struct stat fileinfo;
    source_entry_t *myentry;
    int numchanged;

    sshguard_log(LOG_DEBUG, "Checking for inactive sources...");

    numchanged = 0;
    list_iterator_start(& sources_list);
    while (list_iterator_hasnext(& sources_list)) {
        myentry = (source_entry_t *)list_iterator_next(& sources_list);

        if (myentry->active) continue;

        if (stat(myentry->filename, & fileinfo) == 0) {
            /* source is back! */
            sshguard_log(LOG_NOTICE, "Source '%s' reappeared. Reloading.", myentry->filename);
            if (activate_source(myentry, & fileinfo) == 0)
                ++numchanged;
        }
    }
    list_iterator_stop(& sources_list);

    sshguard_log(LOG_INFO, "Quick refresh showed %u redeemable sources.", numchanged);

    if (numchanged > 0) {
        /* update kqueue events to reflect new source configuration */
        set_kevs();
    }

    return 0;
}
#endif


static int refresh_files() {
    struct stat fileinfo;
    source_entry_t *myentry;
    unsigned int numchanged = 0;
#if defined(HAVE_KQUEUE)
    unsigned int kevs_num = 0;
#endif

    sshguard_log(LOG_DEBUG, "Checking to refresh sources...");

    /* get all updated serial numbers */
    list_iterator_start(& sources_list);
    while (list_iterator_hasnext(& sources_list)) {
        myentry = (source_entry_t *)list_iterator_next(& sources_list);

        /* skip stdin */
        if (myentry->current_descriptor == STDIN_FILENO) continue;

        /* check the current serial number of the filename */
        if (stat(myentry->filename, & fileinfo) != 0) {
            /* source no longer present */
            if (myentry->active) {
                deactivate_source(myentry);
                ++numchanged;
            }
            continue;
        }

        /* no news good news? */
        if (myentry->active && myentry->current_serial_number == fileinfo.st_ino) continue;

        /* there are news. Sort out if reappeared or rotated */
        ++numchanged;
        if (! myentry->active) {
            /* entry was inactive, now available. Resume it */
            sshguard_log(LOG_NOTICE, "Source '%s' reappeared. Reloading.", myentry->filename);
        } else {
            /* rotated (ie myentry->current_serial_number != fileinfo.st_ino) */
            sshguard_log(LOG_NOTICE, "Reloading rotated file %s.", myentry->filename);
            deactivate_source(myentry);
        }
        activate_source(myentry, & fileinfo);

        /* descriptor and source ready! */
#if defined(HAVE_KQUEUE)
        if (myentry->current_descriptor != STDIN_FILENO) {
            /* this is a file. Monitor deletion/renaming as well */
			EV_SET(& kevs[kevs_num], myentry->current_descriptor, EVFILT_VNODE,
			    EV_ADD | EV_ENABLE | EV_CLEAR,
			    NOTE_DELETE | NOTE_RENAME, 0, 0);
            ++kevs_num;
        }
        EV_SET(& kevs[kevs_num], myentry->current_descriptor, EVFILT_READ,
                EV_ADD | EV_ENABLE | EV_CLEAR,
                0,
                0, 0);
        /* sshguard_log(LOG_DEBUG, "Setting event for %s.", myentry->filename); */

        ++kevs_num;
#endif
    }
    list_iterator_stop(& sources_list);

    sshguard_log(LOG_INFO, "Refreshing sources showed %u changes.", numchanged);

#if defined(HAVE_KQUEUE)
    if (numchanged > 0) {
        /* register filters for new sources */
        sshguard_log(LOG_DEBUG, "Setting %u events for %u active sources.", kevs_num, num_sources_active);
        if (kevent(kq, kevs, kevs_num, NULL, 0, NULL) < 0) {
            sshguard_log(LOG_ERR, "Cannot configure kqueue() events! %s.", strerror(errno));
        }
    }
#endif

    return 0;
}

static int activate_source(source_entry_t *restrict srcent, const struct stat *fileinfo) {
    assert(srcent != NULL);
    assert(fileinfo != NULL);

    srcent->current_descriptor = open(srcent->filename, O_RDONLY | O_NONBLOCK);
    if (srcent->current_descriptor < 0) {
        sshguard_log(LOG_ERR, "Ouch!! File '%s' lost (%s)! Archiving it for later attempts.", srcent->filename, strerror(errno));
        return -1;
    }
    srcent->current_serial_number = fileinfo->st_ino;
    srcent->active = 1;

    ++num_sources_active;

    return 0;
}

static void deactivate_source(source_entry_t *restrict s) {
    if (! s->active) return;

    sshguard_log(LOG_DEBUG, "Deactivating file '%s'.", s->filename);
    close(s->current_descriptor);
    s->active = 0;
    --num_sources_active;
}

#if defined(HAVE_KQUEUE)
static void set_kevs() {
    int i;
    unsigned int kevs_num = 0;
    const source_entry_t *source;


    sshguard_log(LOG_DEBUG, "Registering events.");

    /* prepare event list */
    list_iterator_start(& sources_list);
    for (i = 0; list_iterator_hasnext(& sources_list); ++i) {
        /* add event to queue */
        source = (const source_entry_t *)list_iterator_next(& sources_list);
        if (! source->active) continue;

        if (source->current_descriptor != STDIN_FILENO) {
            /* this is a file. Monitor deletion/renaming as well */
			EV_SET(& kevs[kevs_num], source->current_descriptor, EVFILT_VNODE,
			    EV_ADD | EV_ENABLE | EV_CLEAR,
			    NOTE_DELETE | NOTE_RENAME, 0, 0);
            ++kevs_num;
        }
        EV_SET(& kevs[kevs_num], source->current_descriptor, EVFILT_READ,
                EV_ADD | EV_ENABLE | EV_CLEAR,
                0,
                0, 0);
        /* sshguard_log(LOG_DEBUG, "Setting event for %s.", source->filename); */

        ++kevs_num;
    }
    list_iterator_stop(& sources_list);
    
    /* configure kqueue with the given events */
    sshguard_log(LOG_DEBUG, "Setting %u events for %u (act+inact) files.", kevs_num, i);
	if (kevent(kq, kevs, kevs_num, NULL, 0, NULL) < 0) {
        sshguard_log(LOG_ERR, "Cannot configure kqueue() events! %s.", strerror(errno));
	}
}


#endif
