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
#include <sys/stat.h>
/* to sleep POSIX-compatibly with select() */
#include <sys/time.h>

#include "sshguard.h"
#include "sshguard_log.h"

#include "sshguard_logsuck.h"

/* do enable it! */
#define LOGSUCK_DISAPPEARING_FILES


/* filenames of files to poll */
static char *restrict sucked_filenames[MAX_FILES_POLLED];
/* descriptors of files to poll */
static int sucked_file_descriptors[MAX_FILES_POLLED];
/* filesystem IDs of files to poll (used for detecting rotation) */
static int sucked_serial_nums[MAX_FILES_POLLED];
/* how many files we are actively polling (may decrease at runtime if some "disappear" */
static int num_files_active = 0;
/* index of last file polled (used if insisting on source is required) */
static int index_last_read = -1;

#ifdef LOGSUCK_DISAPPEARING_FILES
/* file names of files that disappeared at runtime */
static char *restrict disappeared_sucked_filename[MAX_FILES_POLLED];
#endif


/* read a line from a file descriptor into a buffer */
static int read_from(int index, char *restrict buf, size_t buflen);
static void get_serial_numbers(int serials_array[]);
#ifdef LOGSUCK_DISAPPEARING_FILES
static int num_disappeared_files = 0;
static void archive_file(int index);
static void redeem_disappeared_files();
#endif

static int refresh_files();

int logsuck_init() {
    return 0;
}

int logsuck_add_logfile(const char *restrict filename) {
    int curfd;

    assert(filename != NULL);

    sshguard_log(LOG_DEBUG, "Adding '%s' to polled files.", filename);

    if (strcmp(filename, "-") == 0) {
        /* read from standard input */
        curfd = 0;
    } else {
        /* open file */
        curfd = open(filename, O_RDONLY | O_NONBLOCK);
        if (curfd == -1) {
            sshguard_log(LOG_ERR, "Unable to open '%s': %s.", filename, strerror(errno));
            return -1;
        }
        /* move to the end of file */
        lseek(curfd, 0, SEEK_END); /* safe to fail if file is named pipe */
    }

    /* add fd to list */
    sucked_file_descriptors[num_files_active] = curfd;
    
    /* save filename */
    sucked_filenames[num_files_active] = malloc(strlen(filename)+1);
    assert(sucked_filenames[num_files_active] != NULL);
    strcpy(sucked_filenames[num_files_active], filename);

    ++num_files_active;
    get_serial_numbers(sucked_serial_nums);

    sshguard_log(LOG_DEBUG, "File '%s' added, fd %d, serial %u.", filename, sucked_file_descriptors[num_files_active-1], sucked_serial_nums[num_files_active-1]);

    return 0;
}

int logsuck_getline(char *restrict buf, size_t buflen, bool from_previous_source) {
    int ret, sleep_interval;
    struct timeval sleepstruct;

    if (num_files_active <= 0) {
        sshguard_log(LOG_ERR, "No files to be polled! Trying to redeem some.");
        sleep(3);
        redeem_disappeared_files();
        if (num_files_active <= 0) return -1;
    }

    if (from_previous_source && index_last_read > 0) {
        sshguard_log(LOG_DEBUG, "Sticking to '%s' to get next line.", sucked_filenames[index_last_read]);
        return read_from(index_last_read, buf, buflen);
    }

    /* poll files until some stuff is read (in random order, until data is found) */
    sleep_interval = 800;
    while (1) {
        int pos, start;

#ifdef LOGSUCK_DISAPPEARING_FILES
        /* occasionally attempt to redeem disappeared files */
        if (num_disappeared_files > 0) {
            if (rand() % 5 == 0) redeem_disappeared_files();
        }
#endif

        /* pass through all files avoiding starvation */
        start = rand() % num_files_active;
        for (pos = start; pos < num_files_active + start; ++pos) {
            index_last_read = pos % num_files_active;
            ret = read(sucked_file_descriptors[index_last_read], & buf[0], 1);
            switch (ret) {
                case 1:
                    /* there is stuff. Read rest of the line */
                    sshguard_log(LOG_DEBUG, "Read line from '%s'.", sucked_filenames[index_last_read]);
                    return read_from(index_last_read, & buf[1], buflen-1);

                case -1:
                    if (errno != EAGAIN) {
                        /* error */
                        sshguard_log(LOG_NOTICE, "Error while reading from file '%s': %s.", sucked_filenames[index_last_read], strerror(errno));
#ifdef LOGSUCK_DISAPPEARING_FILES
                        archive_file(index_last_read);
                        --pos;
#endif
                    }
            }
        }
        /* no data. Wait for something with exponential backoff, up to LOGSUCK_MAX_WAIT */
        sshguard_log(LOG_DEBUG, "Nothing new on any file. Wait %d millisecs for new data.", sleep_interval);
        /* sleep, POSIX-compatibly */
        sleepstruct.tv_sec = sleep_interval / 1000;
        sleepstruct.tv_usec = (sleep_interval % 1000)*1000;
        select(0, NULL, NULL, NULL, & sleepstruct);
        sleep_interval = (sleep_interval*2 < MAX_LOGPOLL_INTERVAL ? sleep_interval*2 : MAX_LOGPOLL_INTERVAL);
        refresh_files();
    }

    return 0;
}

int logsuck_fin() {
    int i;

    /* close all files */
    for (i = 0; i < num_files_active; ++i) {
        close(sucked_file_descriptors[i]);
        free(sucked_filenames[i]);
    }

    return 0;
}

static int read_from(int index, char *restrict buf, size_t buflen) {
    int i, ret, fd;
    int old_flags;

    /* extract file descriptor to read from */
    fd = sucked_file_descriptors[index];

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
    if (buf[i-1] != '\n') {
        sshguard_log(LOG_ERR, "Unable to read full line from '%s': %s.", sucked_file_descriptors[fd], strerror(errno));
        return -1;
    }
    if (i >= buflen) {
        sshguard_log(LOG_ERR, "Increase buffer, %d was insufficient for '%s'.", buflen, buf);
        return -1;
    }

    return 0;
}

static int refresh_files() {
    int i;
    int updated_serials[MAX_FILES_POLLED];

    /* get all updated serial numbers */
    get_serial_numbers(updated_serials);
    for (i = 0; i < num_files_active; ++i) {
        if (sucked_serial_nums[i] != updated_serials[i]) {
            /* reopen */
            sshguard_log(LOG_NOTICE, "Reloading rotated file %s.", sucked_filenames[i]);
            close(sucked_file_descriptors[i]);
            sucked_file_descriptors[i] = open(sucked_filenames[i], O_RDONLY | O_NONBLOCK);
            if (sucked_file_descriptors[i] < 0) {
                sshguard_log(LOG_ERR, "Ouch!! File '%s' lost (%s)! Archiving it for later attempts.", sucked_filenames[i], strerror(errno));
#ifdef LOGSUCK_DISAPPEARING_FILES
                archive_file(i);
#endif
                continue;
            }
        }
    }
    /* update serials with newly opened files */
    get_serial_numbers(sucked_serial_nums);

    return 0;
}

static void get_serial_numbers(int serials_array[]) {
    int i;
    struct stat fileinfo;

    for (i = 0; i < num_files_active; ++i) {
        if (sucked_file_descriptors[i] == 0) {
            /* the stdin pipe */
            serials_array[i] = 0;
        } else {
            /* a file */
            if (stat(sucked_filenames[i], & fileinfo) != 0) {
                /* file does not exist anymore, "archive" it */
                sshguard_log(LOG_ERR, "Ouch!! File '%s' disappeared! Archiving it for later attempts.", sucked_filenames[i]);
#ifdef LOGSUCK_DISAPPEARING_FILES
                archive_file(i);
#endif
                continue;
            }
            serials_array[i] = fileinfo.st_ino;
        }
    }
}

#ifdef LOGSUCK_DISAPPEARING_FILES
static void archive_file(int index) {
    /* archive filename */
    disappeared_sucked_filename[num_disappeared_files] = sucked_filenames[index];
    sucked_filenames[index] = sucked_filenames[num_files_active-1];

    /* dispose of file descriptor */
    sucked_file_descriptors[index] = sucked_file_descriptors[num_files_active-1];

    /* dispose of serial number */
    sucked_serial_nums[index] = sucked_serial_nums[num_files_active-1];

    /* dispose file itself if it's the "magic" standard input */
    if (strcmp(disappeared_sucked_filename[num_disappeared_files], "-") != 0) {
        --num_files_active;
        ++num_disappeared_files;
    }
}


static void redeem_disappeared_files() {
    int i, fd;

    sshguard_log(LOG_DEBUG, "Rescanning %d disappeared files.", num_disappeared_files);

    /* try to redeem each */
    for (i = 0; i < num_disappeared_files; ++i) {
        fd = open(disappeared_sucked_filename[i], O_RDONLY);
        if (fd >= 0) {
            /* it's back! */
            sshguard_log(LOG_DEBUG, "File '%s' reappeared. Reloaded.", disappeared_sucked_filename[i]);
            /* move it back to the alive data structures */
            sucked_file_descriptors[num_files_active] = fd;
            sucked_filenames[num_files_active] = disappeared_sucked_filename[i];
            /* remove this file from end */
            disappeared_sucked_filename[i] = disappeared_sucked_filename[num_disappeared_files-1];
            disappeared_sucked_filename[num_disappeared_files-1] = NULL;
            ++num_files_active;
            --num_disappeared_files;
            /* ensure to process the new file next */
            --i;
        }
    }

    get_serial_numbers(sucked_serial_nums);
}
#endif

