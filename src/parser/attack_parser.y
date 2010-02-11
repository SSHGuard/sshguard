%{

/*
 * Copyright (c) 2007,2008,2009,2010 Mij <mij@bitchx.it>
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
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>


#include "../sshguard_log.h"
#include "../sshguard_procauth.h"
#include "../sshguard_logsuck.h"

 /* get to know MAX_FILES_POLLED */
#include "../sshguard.h"

#include "../parser.h"

 /* stuff exported by the scanner */
extern void scanner_init();
extern void scanner_fin();
extern int yylex();

 /* my function for reporting parse errors */
static void yyerror(int source_id, const char *msg);

 /* Metadata used by the parser */
 /* per-source metadata */
typedef struct {
    sourceid_t id;
    int last_was_recognized;
    attack_t last_attack;
    unsigned int last_multiplicity;
} source_metadata_t;

 /* parser metadata */
static struct {
    unsigned int num_sources;
    int current_source_index;
    source_metadata_t sources[MAX_FILES_POLLED];
} parser_metadata = { 0, -1 };

%}

 /* parameter to the parsing function */
%parse-param        { const int source_id };

/* %pure-parser */
%start text

%union {
    char *str;
    int num;
}

/* semantic values for tokens */
%token <str> IPv4 IPv6 HOSTADDR WORD
%token <num> INTEGER SYSLOG_BANNER_PID LAST_LINE_REPEATED_N_TIMES

/* flat tokens */
%token SYSLOG_BANNER TIMESTAMP_SYSLOG TIMESTAMP_TAI64 METALOG_BANNER
/* ssh */
%token SSH_INVALUSERPREF SSH_NOTALLOWEDPREF SSH_NOTALLOWEDSUFF
%token SSH_LOGINERR_PREF SSH_LOGINERR_SUFF SSH_LOGINERR_PAM
%token SSH_REVERSEMAP_PREF SSH_REVERSEMAP_SUFF
%token SSH_NOIDENTIFSTR SSH_BADPROTOCOLIDENTIF
/* dovecot */
%token DOVECOT_IMAP_LOGINERR_PREF DOVECOT_IMAP_LOGINERR_SUFF
/* uwimap */
%token UWIMAP_LOGINERR
/* cyrus-imap */
%token CYRUSIMAP_SASL_LOGINERR_PREF CYRUSIMAP_SASL_LOGINERR_SUFF
/* cucipop */
%token CUCIPOP_AUTHFAIL
/* exim */
%token EXIM_ESMTP_AUTHFAIL_PREF EXIM_ESMTP_AUTHFAIL_SUFF
/* sendmail */
%token SENDMAIL_RELAYDENIED_PREF SENDMAIL_RELAYDENIED_SUFF
/* FreeBSD's FTPd */
%token FREEBSDFTPD_LOGINERR_PREF FREEBSDFTPD_LOGINERR_SUFF
/* proFTPd */
%token PROFTPD_LOGINERR_PREF PROFTPD_LOGINERR_SUFF
/* PureFTPd */
%token PUREFTPD_LOGINERR_PREF PUREFTPD_LOGINERR_SUFF
/* vsftpd */
%token VSFTPD_LOGINERR_PREF VSFTPD_LOGINERR_SUFF

/* msg_multiple returns the multiplicity degree of its recognized message */
%type <num> msg_multiple

%%

/* log source */
text:
    syslogent
    | multilogent
    | metalogent
    | logmsg
    ;

/**         BEGIN OF "LIBRARY" RULES        **/

/* a syslog-generated log entry */
/* EFFECT:
 * - the target address is stored in parsed_attack.address.value
 * - the target address kind is stored in parsed_attack.address.kind
 */
syslogent:
     /* timestamp hostname procname[pid]: logmsg */
    /*TIMESTAMP_SYSLOG hostname procname '[' INTEGER ']' ':' logmsg   {*/
    SYSLOG_BANNER_PID logmsg {
                        /* reject to accept if the pid has been forged */
                        if (procauth_isauthoritative(parsed_attack.service, $1) == -1) {
                            /* forged */
                            sshguard_log(LOG_NOTICE, "Ignore attack as pid '%d' has been forged for service %d.", $1, parsed_attack.service);
                            YYABORT;
                        }
                    }

    /*| TIMESTAMP_SYSLOG hostname procname ':' logmsg*/
    | SYSLOG_BANNER logmsg
    ;

/* a multilog-generated log entry */
multilogent:
    '@' TIMESTAMP_TAI64 logmsg
    ;

metalogent:
    METALOG_BANNER logmsg
    ;

/* the "payload" of a log entry: the oridinal message generated from a process */
logmsg:
      /* individual messages */
    msg_single          {   parser_metadata.sources[parser_metadata.current_source_index].last_multiplicity = 1;    }
      /* messages with repeated attacks -- eg syslog's "last line repeated N times" */
    | msg_multiple      {   parser_metadata.sources[parser_metadata.current_source_index].last_multiplicity = $1; }
    ;

msg_single:
    sshmsg              {   parsed_attack.service = SERVICES_SSH; }
    | dovecotmsg        {   parsed_attack.service = SERVICES_DOVECOT; }
    | uwimapmsg         {   parsed_attack.service = SERVICES_UWIMAP; }
    | cyrusimapmsg      {   parsed_attack.service = SERVICES_CYRUSIMAP; }
    | cucipopmsg        {   parsed_attack.service = SERVICES_CUCIPOP; }
    | eximmsg           {   parsed_attack.service = SERVICES_EXIM; }
    | sendmailmsg       {   parsed_attack.service = SERVICES_SENDMAIL; }
    | freebsdftpdmsg    {   parsed_attack.service = SERVICES_FREEBSDFTPD; }
    | proftpdmsg        {   parsed_attack.service = SERVICES_PROFTPD; }
    | pureftpdmsg       {   parsed_attack.service = SERVICES_PUREFTPD; }
    | vsftpdmsg         {   parsed_attack.service = SERVICES_VSFTPD; }
    ;

msg_multiple:
    /* syslog style  "last message repeated N times"  message */
    LAST_LINE_REPEATED_N_TIMES     {
                        /* the message repeated, was it an attack? */
                        if (! parser_metadata.sources[parser_metadata.current_source_index].last_was_recognized) {
                            /* make sure this doesn't get recognized as an attack */
                            YYABORT;
                        }
                        
                        /* got a repeated attack */
                        parsed_attack = parser_metadata.sources[parser_metadata.current_source_index].last_attack;
                        /* restore previous "genuine" dangerousness, and build new one */
                        parsed_attack.dangerousness = $1 * (parsed_attack.dangerousness / parser_metadata.sources[parser_metadata.current_source_index].last_multiplicity);

                        /* pass up the multiplicity of this attack */
                        $$ = $1;
                    }
    ;

/* an address */
addr:
    IPv4            {
                        parsed_attack.address.kind = ADDRKIND_IPv4;
                        strcpy(parsed_attack.address.value, $1);
                    }
    | IPv6          {
                        parsed_attack.address.kind = ADDRKIND_IPv6;
                        strcpy(parsed_attack.address.value, $1);
                    }
    | HOSTADDR      {
                        struct addrinfo addrinfo_hints;
                        struct addrinfo *addrinfo_result;
                        int res;

                        /* look up IPv4 first */
                        memset(& addrinfo_hints, 0x00, sizeof(addrinfo_hints));
                        addrinfo_hints.ai_family = AF_INET;
                        res = getaddrinfo($1, NULL, & addrinfo_hints, & addrinfo_result);
                        if (res == 0) {
                            struct sockaddr_in *foo4;
                            /* pick the first (IPv4) result address and return */
                            parsed_attack.address.kind = ADDRKIND_IPv4;
                            foo4 = (struct sockaddr_in *)(addrinfo_result->ai_addr);
                            if (inet_ntop(AF_INET, & foo4->sin_addr, parsed_attack.address.value, addrinfo_result->ai_addrlen) == NULL) {
                                freeaddrinfo(addrinfo_result);
                                sshguard_log(LOG_ERR, "Unable to interpret resolution result as IPv4 address: %s. Giving up entry.", strerror(errno));
                                YYABORT;
                            }
                        } else {
                            sshguard_log(LOG_DEBUG, "Failed to resolve '%s' @ IPv4! Trying IPv6.", $1);
                            /* try IPv6 */
                            addrinfo_hints.ai_family = AF_INET6;
                            res = getaddrinfo($1, NULL, & addrinfo_hints, & addrinfo_result);
                            if (res == 0) {
                                struct sockaddr_in6 *foo6;
                                /* pick the first (IPv6) result address and return */
                                parsed_attack.address.kind = ADDRKIND_IPv6;
                                foo6 = (struct sockaddr_in6 *)(addrinfo_result->ai_addr);
                                if (inet_ntop(AF_INET6, & foo6->sin6_addr, parsed_attack.address.value, addrinfo_result->ai_addrlen) == NULL) {
                                    sshguard_log(LOG_ERR, "Unable to interpret resolution result as IPv6 address: %s. Giving up entry.", strerror(errno));
                                    freeaddrinfo(addrinfo_result);
                                    YYABORT;
                                }
                            } else {
                                sshguard_log(LOG_ERR, "Could not resolv '%s' in neither of IPv{4,6}. Giving up entry.", $1);
                                freeaddrinfo(addrinfo_result);
                                YYABORT;
                            }
                        }

                        sshguard_log(LOG_INFO, "Successfully resolved '%s' --> %d:'%s'.",
                                $1, parsed_attack.address.kind, parsed_attack.address.value);
                        freeaddrinfo(addrinfo_result);
                    }
    ;

/**         END OF "LIBRARY" RULES          **/

/* attack rules for SSHd */
sshmsg:
    /* login attempt from non-existent user, or from existent but non-allowed user */
    ssh_illegaluser
    /* incorrect login attempt from valid and allowed user */
    | ssh_authfail
    | ssh_reversemapping
    | ssh_noidentifstring
    | ssh_badprotocol
    ;

ssh_illegaluser:
    /* nonexistent user */
    SSH_INVALUSERPREF addr
    /* existent, unallowed user */
    | SSH_NOTALLOWEDPREF addr SSH_NOTALLOWEDSUFF
    ;

ssh_authfail:
    SSH_LOGINERR_PREF addr SSH_LOGINERR_SUFF
    | SSH_LOGINERR_PAM addr
    ;

ssh_reversemapping:
    SSH_REVERSEMAP_PREF addr SSH_REVERSEMAP_SUFF
    ;

ssh_noidentifstring:
    SSH_NOIDENTIFSTR addr
    ;

ssh_badprotocol:
    SSH_BADPROTOCOLIDENTIF addr
    ;

/* attack rules for dovecot imap */
dovecotmsg:
    DOVECOT_IMAP_LOGINERR_PREF addr DOVECOT_IMAP_LOGINERR_SUFF
    ;

/* attack rules for UWIMAP */
uwimapmsg:
    UWIMAP_LOGINERR '[' addr ']'
    ;

cyrusimapmsg:
    CYRUSIMAP_SASL_LOGINERR_PREF addr CYRUSIMAP_SASL_LOGINERR_SUFF
    ;

/* cucipop reports @addr@ tried to log in with wrong password */
cucipopmsg:
    CUCIPOP_AUTHFAIL addr
    ;

/* */
eximmsg:
   EXIM_ESMTP_AUTHFAIL_PREF addr EXIM_ESMTP_AUTHFAIL_SUFF
   ;

sendmailmsg:
   SENDMAIL_RELAYDENIED_PREF addr SENDMAIL_RELAYDENIED_SUFF;
   ;

/* attack rules for FreeBSD's ftpd */
freebsdftpdmsg:
    FREEBSDFTPD_LOGINERR_PREF addr FREEBSDFTPD_LOGINERR_SUFF
    ;

/* attack rules for ProFTPd */
proftpdmsg:
    PROFTPD_LOGINERR_PREF addr PROFTPD_LOGINERR_SUFF
    ;

/* attack rules for Pure-FTPd */
pureftpdmsg:
    PUREFTPD_LOGINERR_PREF addr PUREFTPD_LOGINERR_SUFF
    ;

/* attack rules for vsftpd */
vsftpdmsg:
    VSFTPD_LOGINERR_PREF addr VSFTPD_LOGINERR_SUFF
    ;

%%

static void yyerror(int source_id, const char *msg) { /* do nothing */ }

static void init_structures(int source_id) {
    int cnt;

    /* add metadata for this source, if new */
    for (cnt = 0; cnt < parser_metadata.num_sources; ++cnt) {
        if (parser_metadata.sources[cnt].id == source_id) break;
    }
    if (cnt == parser_metadata.num_sources) {
        /* new source! */
        assert(cnt < MAX_FILES_POLLED);
        parser_metadata.sources[cnt].id = source_id;
        parser_metadata.sources[cnt].last_was_recognized = 0;
        parser_metadata.sources[cnt].last_multiplicity = 1;

        parser_metadata.num_sources++;
    }
    
    /* initialize the attack structure */
    parsed_attack.dangerousness = DEFAULT_ATTACKS_DANGEROUSNESS;

    /* set current source index */
    parser_metadata.current_source_index = cnt;
}

int parse_line(int source_id, char *str) {
    int ret;

    /* initialize parser structures */
    init_structures(source_id);

    /* initialize scanner, do parse, finalize scanner */
    scanner_init(str);
    ret = yyparse(source_id);
    scanner_fin();

    /* do post-parsing oeprations */
    if (ret == 0) {
        /* message recognized */
        /* update metadata on this source */
        parser_metadata.sources[parser_metadata.current_source_index].last_was_recognized = 1;
        parser_metadata.sources[parser_metadata.current_source_index].last_attack = parsed_attack;
    } else {
        /* message not recognized */
        parser_metadata.sources[parser_metadata.current_source_index].last_was_recognized = 0;
    }

    return ret;
}


