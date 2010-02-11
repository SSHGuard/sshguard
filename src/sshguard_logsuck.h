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

#ifndef SSHGUARD_LOGSUCK_H
#define SSHGUARD_LOGSUCK_H

#include <stdbool.h>

typedef uint32_t sourceid_t;

/**
 * Initialize the logsuck subsystem.
 *
 * @return 0 on success, -1 on error
 */
int logsuck_init();

/**
 * Add a log file to be polled.
 *
 * @return 0 on success, -1 on error
 */
int logsuck_add_logsource(const char *restrict filename);

/**
 * Get the first whole log line coming from any log file configured.
 *
 * @param from_previous_source  read from the same source of previous message
 *
 * @return 0 on success, -1 on error
 */
int logsuck_getline(char *restrict buf, size_t buflen, bool from_previous_source, sourceid_t *restrict whichsource);

/**
 * Finalize the logsuck subsystem.
 *
 * @return 0 on success, -1 on error
 */
int logsuck_fin();

#endif

