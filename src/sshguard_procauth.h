/*
 * Copyright (c) 2007,2008 Mij <mij@sshguard.net>
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

#ifndef SSHGUARD_PROCAUTH_H
#define SSHGUARD_PROCAUTH_H

#include <sys/types.h>

#include "sshguard_services.h"

/* initialize the procauth subsystem */
int procauth_init();

/* finalize the procauth subsystem */
int procauth_fin();

/* add a process to the list of authorizable given its configuration.
 * Configuration format is: "digit:string", meaning: service_code:pid_filename
 * service_code associates the process to a given service, see sshguard_services.h
 */
int procauth_addprocess(char *conf);

/*
 * refresh the cache of process pids by traversing their pidfiles
 * return the number of pids changed
 */
int procauth_refreshpids();

/* checks if "pid" is the authoritative process for service "service_code"
 * return:
 *    1 if authoritative
 *    -1 if NOT authoritative
 *    0 if no answer can be determined (service_code not configured or other error)
 */
int procauth_isauthoritative(int service_code, pid_t pid);


#endif

