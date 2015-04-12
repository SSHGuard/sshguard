/*
 * Copyright (c) 2007,2008,2009,2010 Mij <mij@sshguard.net>
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

enum service {
    SERVICES_ALL            = 0,    //< anything
    SERVICES_SSH            = 100,  //< ssh
    SERVICES_UWIMAP         = 200,  //< UWimap for imap and pop daemon
    SERVICES_DOVECOT        = 210,  //< dovecot
    SERVICES_CYRUSIMAP      = 220,  //< cyrus-imap
    SERVICES_CUCIPOP        = 230,  //< cucipop
    SERVICES_EXIM           = 240,  //< exim
    SERVICES_SENDMAIL       = 250,  //< sendmail
    SERVICES_POSTFIX        = 260,  //< postfix
    SERVICES_FREEBSDFTPD    = 300,  //< ftpd shipped with FreeBSD
    SERVICES_PROFTPD        = 310,  //< ProFTPd
    SERVICES_PUREFTPD       = 320,  //< Pure-FTPd
    SERVICES_VSFTPD         = 330,  //< vsftpd
};

#endif
