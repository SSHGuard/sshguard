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

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
    ino_t last_inode;    //< File inode for rotation detection
} source_entry_t;

/* list of source_entry_t elements */
static list_t sources_list;

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
static size_t list_meter_sourceentry() {
    return sizeof(source_entry_t);
}

int logsuck_init() {
    list_init(& sources_list);
    list_attributes_copy(& sources_list, list_meter_sourceentry, 1);
    return 0;
}

int logsuck_add_logsource(const char *restrict filename) {
    source_entry_t cursource;

    assert(filename != NULL);
    if (list_size(& sources_list) >= MAX_FILES_POLLED) {
        sshguard_log(LOG_CRIT, "I can monitor at most %u files! See MAX_FILES_POLLED.", MAX_FILES_POLLED);
        return -1;
    }

    /* store filename */
    strcpy(cursource.filename, filename);

    /* compute source id (based on filename) */
    cursource.source_id = fnv_32a_str(filename, 0);

    /* open and store file descriptor */
    if (strcmp(filename, "-") == 0) {
        int fflags;
        /* read from standard input */
        cursource.current_descriptor = STDIN_FILENO;
        cursource.last_inode = 0;
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
        if (stat(filename, &fileinfo) != 0) {
            fileinfo.st_ino = 0;
        }
        activate_source(&cursource, &fileinfo);
        lseek(cursource.current_descriptor, 0, SEEK_END);
    }

    /* do add */
    list_append(& sources_list, & cursource);

    sshguard_log(LOG_DEBUG, "File '%s' added, fd %d, serial %lu.", filename,
                 cursource.current_descriptor,
                 (unsigned long)cursource.last_inode);

    return 0;
}

int logsuck_getline(char *restrict buf, size_t buflen, sourceid_t *restrict whichsource) {
    int ret;
    /* use active poll through non-blocking read()s */
    int sleep_interval;
    source_entry_t *restrict readentry;

    /* poll all files until some stuff is read (in random order, until data is found) */
    sleep_interval = 20;
    while (1) {
        unsigned int pos, start;

        /* attempt to redeem disappeared files */
        refresh_files();

        /* pass through all files avoiding starvation */
        start = rand() % list_size(& sources_list);

        for (pos = start; pos < list_size(& sources_list) + start; ++pos) {
            index_last_read = pos % list_size(& sources_list);
            readentry = (source_entry_t *restrict)list_get_at(& sources_list, index_last_read);
            if (! readentry->active) continue;
            ret = read(readentry->current_descriptor, & buf[0], 1);
            switch (ret) {
                case 1:
                    /* ignore blank lines */
                    if (buf[0] == '\n') continue;
                    /* there is stuff. Read rest of the line */
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
        usleep(sleep_interval * 1000);
        /* update sleep interval for next call */
        if (sleep_interval < MAX_LOGPOLL_INTERVAL) {
            sleep_interval = sleep_interval + 1+(LOGPOLL_INTERVAL_GROWTHFACTOR*sleep_interval);
            if (sleep_interval > MAX_LOGPOLL_INTERVAL)
                sleep_interval = MAX_LOGPOLL_INTERVAL;
        }
    }

    /* we shouldn't be here, or there is an error */
    return -1;
}

void logsuck_fin() {
    source_entry_t *restrict myentry;

    /* close all files and release memory for metadata */
    list_iterator_start(& sources_list);
    while (list_iterator_hasnext(& sources_list)) {
        myentry = (source_entry_t *restrict)list_iterator_next(& sources_list);

        close(myentry->current_descriptor);
    }
    list_iterator_stop(& sources_list);
    list_destroy(& sources_list);
}


static int read_from(const source_entry_t *restrict source, char *restrict buf, size_t buflen) {
    unsigned int i, ret, bullets;

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
    } while (buf[i-1] != '\n' && i < buflen-2 && bullets > 0);
    buf[i] = '\0';
    if (bullets == 0) {
        /* what's up with the writer? read() patiented forever! Discard this entry. */
        sshguard_log(LOG_INFO, "Discarding partial log entry '%s': source %u cannot starve the others.", buf, source->source_id);
        buf[0] = '\0';
        return -1;
    }
    /* check result */
    if (i >= buflen) {
        sshguard_log(LOG_ERR, "Increase buffer, %lu was insufficient for '%s'.", (long unsigned int)buflen, buf);
        return -1;
    }

    return 0;
}

static int refresh_files() {
    struct stat fileinfo;
    source_entry_t *myentry;
    unsigned int numchanged = 0;

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

        if (myentry->active && myentry->last_inode == fileinfo.st_ino) {
            // File inode did not change; log was not rotated.
            continue;
        }

        /* there are news. Sort out if reappeared or rotated */
        ++numchanged;
        if (! myentry->active) {
            /* entry was inactive, now available. Resume it */
        } else {
            /* rotated (ie myentry->last_inode != fileinfo.st_ino) */
            sshguard_log(LOG_NOTICE, "Reloading rotated file %s.", myentry->filename);
            deactivate_source(myentry);
        }
        activate_source(myentry, & fileinfo);

        /* descriptor and source ready! */
    }
    list_iterator_stop(& sources_list);
    return 0;
}

static int activate_source(source_entry_t *restrict srcent, const struct stat *fileinfo) {
    assert(srcent != NULL);
    assert(fileinfo != NULL);

    srcent->current_descriptor = open(srcent->filename, O_RDONLY | O_NONBLOCK);
    if (srcent->current_descriptor < 0) {
        return -1;
    }
    srcent->last_inode = fileinfo->st_ino;
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
