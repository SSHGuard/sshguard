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

/* factor of growth of the interval between polls while in idle */
#define     LOGPOLL_INTERVAL_GROWTHFACTOR     0.1

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


/* how many files we are actively polling (may decrease at runtime if some "disappear" */
static int num_sources_active = 0;

/* index of last file polled (used if insisting on source is required) */
static int index_last_read = -1;


/* read a line from a file descriptor into a buffer */
static int read_from(const source_entry_t *restrict source, char *restrict buf, size_t buflen);
void deactivate_source(source_entry_t *restrict s);

static int refresh_files();

static size_t list_meter_sourceentry(const void *el) {
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

    sshguard_log(LOG_DEBUG, "Adding '%s' to polled files.", filename);

    /* store filename */
    strcpy(cursource.filename, filename);

    /* compute source id (based on filename) */
    cursource.source_id = fnv_32a_str(filename, 0);

    /* open and store file descriptor */
    if (strcmp(filename, "-") == 0) {
        /* read from standard input */
        cursource.current_descriptor = 0;
        cursource.current_serial_number = 0;
    } else {
        struct stat fileinfo;

        /* open file */
        cursource.current_descriptor = open(filename, O_RDONLY | O_NONBLOCK);
        if (cursource.current_descriptor == -1) {
            sshguard_log(LOG_ERR, "Unable to open '%s': %s.", filename, strerror(errno));
            return -1;
        }
        /* move to the end of file */
        lseek(cursource.current_descriptor, 0, SEEK_END); /* safe to fail if file is named pipe */

        /* get current serial number */
        if (stat(filename, & fileinfo) != 0) {
            sshguard_log(LOG_ERR, "File '%s' vanished while adding!", filename);
            return -1;
        }
        cursource.current_serial_number = fileinfo.st_ino;
    }
    cursource.active = 1;

    /* do add */
    assert(list_append(& sources_list, & cursource) == 1);
    ++num_sources_active;

    sshguard_log(LOG_DEBUG, "File '%s' added, fd %d, serial %u.", filename, cursource.current_descriptor, cursource.current_serial_number);

    return 0;
}

int logsuck_getline(char *restrict buf, size_t buflen, bool from_previous_source, sourceid_t *restrict whichsource) {
    int ret, sleep_interval;
    struct timeval sleepstruct;
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
            ret = read(readentry->current_descriptor, & buf[0], 1);
            switch (ret) {
                case 1:
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
            sleep_interval = sleep_interval+(LOGPOLL_INTERVAL_GROWTHFACTOR*sleep_interval);
            if (sleep_interval > MAX_LOGPOLL_INTERVAL)
                sleep_interval = MAX_LOGPOLL_INTERVAL;
        }
        refresh_files();
    }

    return 0;
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
    int i, ret, fd;
    int old_flags;

    /* extract file descriptor to read from */
    fd = source->current_descriptor;

    /* make blocking, to read rest of the line */
    old_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, old_flags ^ O_NONBLOCK);

    /* read until error, newline reached, or buffer exhausted */
    i = 0;
    do {
        ret = read(fd, & buf[i++], 1);
    } while (ret == 1 && buf[i-1] != '\n' && i < buflen-2);
    buf[i] = '\0';
    /* restore non-blocking flag */
    fcntl(fd, F_SETFL, old_flags);
    /* check result */
    if (buf[i-1] != '\n') {
        sshguard_log(LOG_ERR, "Unable to read full line from '%s': %s.", source->filename, strerror(errno));
        return -1;
    }
    if (i >= buflen) {
        sshguard_log(LOG_ERR, "Increase buffer, %d was insufficient for '%s'.", buflen, buf);
        return -1;
    }

    return 0;
}


static int refresh_files() {
    struct stat fileinfo;
    source_entry_t *myentry;


    /* get all updated serial numbers */
    list_iterator_start(& sources_list);
    while (list_iterator_hasnext(& sources_list)) {
        myentry = (source_entry_t *)list_iterator_next(& sources_list);

        /* check the current serial number of the filename */
        if (stat(myentry->filename, & fileinfo) != 0) {
            deactivate_source(myentry);
            continue;
        }

        if (myentry->current_serial_number != fileinfo.st_ino) {
            /* rotated! Reopen */
            sshguard_log(LOG_NOTICE, "Reloading rotated file %s.", myentry->filename);
            deactivate_source(myentry);
            myentry->current_descriptor = open(myentry->filename, O_RDONLY | O_NONBLOCK);
            if (myentry->current_descriptor < 0) {
                sshguard_log(LOG_ERR, "Ouch!! File '%s' lost (%s)! Archiving it for later attempts.", myentry->filename, strerror(errno));
                continue;
            }
            myentry->current_serial_number = fileinfo.st_ino;
            myentry->active = 1;
            ++num_sources_active;
        }
    }
    list_iterator_stop(& sources_list);

    return 0;
}


void deactivate_source(source_entry_t *restrict s) {
    if (s->active) {
        sshguard_log(LOG_DEBUG, "Deactivating file '%s'.", s->filename);
        close(s->current_descriptor);
        s->active = 0;
        --num_sources_active;
    }
}
