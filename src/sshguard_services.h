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
 * SSHGuard. See http://www.sshguard.net
 */

#ifndef SSHGUARD_SERVICES_H
#define SSHGUARD_SERVICES_H

/* "Any" -- the service attacked is not relevant, block address for everything */
#define SERVICES_ALL                    0


/* SHELL SERVICES */
/* SSH daemon */
#define SERVICES_SSH                    100



/* MAIL SERVICES */
/* UWimap for imap and pop daemon http://www.washington.edu/imap/ */
#define SERVICES_UWIMAP                 200

/* dovecot */
#define SERVICES_DOVECOT                210

/* cyrus-imap */
#define SERVICES_CYRUSIMAP              220

/* cucipop */
#define SERVICES_CUCIPOP                230

/* exim */
#define SERVICES_EXIM                   240

/* FTP SERVICES */
/* ftpd shipped with FreeBSD */
#define SERVICES_FREEBSDFTPD            300

/* ProFTPd */
#define SERVICES_PROFTPD                310

/* Pure-FTPd */
#define SERVICES_PUREFTPD               320

#endif
