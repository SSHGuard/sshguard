%{

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

#include <string.h>

#include "parser.h"

#define DEFAULT_ATTACKS_DANGEROUSNESS           10

 /* stuff exported by the scanner */
extern void scanner_init();
extern void scanner_fin();
extern int yylex();

static void yyerror(attack_t *, const char *);

%}

%parse-param { attack_t *attack }

/* %pure-parser */
%start text

%union {
    char *str;
    int num;
}

/* semantic values for tokens */
%token <str> IPv4 IPv6 HOSTADDR WORD
%token <num> INTEGER SYSLOG_BANNER_PID SOCKLOG_BANNER_PID

/* flat tokens */
%token SYSLOG_BANNER TIMESTAMP_SYSLOG TIMESTAMP_ISO8601 TIMESTAMP_TAI64 AT_TIMESTAMP_TAI64 METALOG_BANNER SOCKLOG_BANNER
%token HTTP_REQUEST HTTP_VERSION HTTP_REDIRECT HTTP_AUTHFAIL HTTP_CLIERROR
%token HTTP_BOTSEARCH_WEBMAIL HTTP_BOTSEARCH_PHPMYADMIN HTTP_BOTSEARCH_WORDPRESS HTTP_BOTSEARCH
/* ssh */
%token SSH_INVALUSERPREF SSH_NOTALLOWEDPREF SSH_NOTALLOWEDSUFF
%token SSH_LOGINERR_PREF SSH_LOGINERR_PAM
%token SSH_VIA
%token SSH_MAXAUTH
%token SSH_ADDR_SUFF
%token SSH_NOIDENTIFSTR SSH_BADPROTOCOLIDENTIF SSH_BADPROTOCOLIDENTIF_SUFF
%token SSH_BADKEX_PREF SSH_BADKEX_SUFF
%token SSH_DISCONNECT_PREF SSH_PREAUTH_SUFF
/* SSHGuard */
%token SSHGUARD_ATTACK_PREF SSHGUARD_ATTACK_SUFF
%token SSHGUARD_BLOCK_PREF SSHGUARD_BLOCK_SUFF
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
%token SENDMAIL_AUTHFAILURE_PREF SENDMAIL_AUTHFAILURE_SUFF
/* postfix */
%token POSTFIX_NO_AUTH_PREF POSTFIX_SASL_LOGINERR_PREF POSTFIX_SASL_LOGINERR_SUFF
/* FreeBSD's FTPd */
%token FREEBSDFTPD_LOGINERR_PREF FREEBSDFTPD_LOGINERR_SUFF
/* proFTPd */
%token PROFTPD_LOGINERR_PREF PROFTPD_LOGINERR_SUFF
/* PureFTPd */
%token PUREFTPD_LOGINERR_PREF PUREFTPD_LOGINERR_SUFF
/* vsftpd */
%token VSFTPD_LOGINERR_PREF VSFTPD_LOGINERR_SUFF
/* cockpit */
%token COCKPIT_AUTHFAIL_PREF COCKPIT_AUTHFAIL_SUFF
/* CLF request */
%token CLF_REQUEST_PREF
/* CLF, unauhtorized */
%token CLF_UNAUTHOIRIZED_PREF CLF_UNAUTHOIRIZED_SUFF
/* CLF, common webapp probes */
%token CLFWEBPROBES_BOTSEARCH_SUFF
/* CLF, WordPress brute-force attacks */
%token CLF_WORDPRESS_SUFF

%%

/* log source */
text:
    syslogent
    | multilogent
    | metalogent
    | socklogent
    | logmsg
    ;

/**         BEGIN OF "LIBRARY" RULES        **/

/* a syslog-generated log entry */
/* EFFECT:
 * - the target address is stored in attack->address.value
 * - the target address kind is stored in attack->address.kind
 */
syslogent:
     /* timestamp hostname procname[pid]: logmsg */
    /*TIMESTAMP_SYSLOG hostname procname '[' INTEGER ']' ':' logmsg   {*/
    SYSLOG_BANNER_PID logmsg

    /*| TIMESTAMP_SYSLOG hostname procname ':' logmsg*/
    | SYSLOG_BANNER logmsg
    ;

/* a multilog-generated log entry */
multilogent:
    AT_TIMESTAMP_TAI64 logmsg
    ;

metalogent:
    METALOG_BANNER logmsg
    ;

/* a socklog-generated log entry */
socklogent:
    SOCKLOG_BANNER_PID logmsg
    | SOCKLOG_BANNER logmsg
    ;

/* the "payload" of a log entry: the oridinal message generated from a process */
logmsg:
    msg_single
    ;

msg_single:
    sshmsg              {   attack->service = SERVICES_SSH; }
    | sshguardmsg       {   attack->service = SERVICES_SSHGUARD; }
    | dovecotmsg        {   attack->service = SERVICES_DOVECOT; }
    | uwimapmsg         {   attack->service = SERVICES_UWIMAP; }
    | cyrusimapmsg      {   attack->service = SERVICES_CYRUSIMAP; }
    | cucipopmsg        {   attack->service = SERVICES_CUCIPOP; }
    | eximmsg           {   attack->service = SERVICES_EXIM; }
    | sendmailmsg       {   attack->service = SERVICES_SENDMAIL; }
    | postfixmsg        {   attack->service = SERVICES_POSTFIX; }
    | freebsdftpdmsg    {   attack->service = SERVICES_FREEBSDFTPD; }
    | proftpdmsg        {   attack->service = SERVICES_PROFTPD; }
    | pureftpdmsg       {   attack->service = SERVICES_PUREFTPD; }
    | vsftpdmsg         {   attack->service = SERVICES_VSFTPD; }
    | cockpitmsg        {   attack->service = SERVICES_COCKPIT; }
    | clfunauhtdmsg     {   attack->service = SERVICES_CLF_UNAUTH; }
    | clfwebprobesmsg   {   attack->service = SERVICES_CLF_PROBES; }
    | clfwordpressmsg   {   attack->service = SERVICES_CLF_WORDPRESS; }
    ;

/* an address */
addr:
    IPv4            {
                        attack->address.kind = ADDRKIND_IPv4;
                        strcpy(attack->address.value, $1);
                    }
    | IPv6          {
                        attack->address.kind = ADDRKIND_IPv6;
                        strcpy(attack->address.value, $1);
                    }
    | HOSTADDR      {
                        if (!attack_from_hostname(attack, $1)) {
                            YYABORT;
                        }
                    }
    ;

/**         END OF "LIBRARY" RULES          **/

/* attack rules for SSHd */
sshmsg:
    /* login attempt from non-existent user, or from existent but non-allowed user */
    ssh_illegaluser
    /* incorrect login attempt from valid and allowed user */
    | ssh_authfail
    | ssh_noidentifstring
    | ssh_badprotocol
    | ssh_badkex
    ;

ssh_illegaluser:
    /* nonexistent user */
    SSH_INVALUSERPREF addr
    | SSH_INVALUSERPREF addr SSH_ADDR_SUFF
    /* existent, unallowed user */
    | SSH_NOTALLOWEDPREF addr SSH_NOTALLOWEDSUFF
    ;

ssh_authfail:
    SSH_LOGINERR_PREF addr SSH_ADDR_SUFF
    | SSH_LOGINERR_PAM addr
    | SSH_LOGINERR_PAM addr SSH_VIA
    | SSH_MAXAUTH addr SSH_ADDR_SUFF
    ;

ssh_noidentifstring:
    SSH_NOIDENTIFSTR addr
    | SSH_DISCONNECT_PREF addr SSH_PREAUTH_SUFF
    ;

ssh_badprotocol:
    SSH_BADPROTOCOLIDENTIF addr SSH_BADPROTOCOLIDENTIF_SUFF
    ;

ssh_badkex:
    SSH_BADKEX_PREF addr SSH_BADKEX_SUFF
    ;

/* attacks and blocks from SSHGuard */
sshguardmsg:
    SSHGUARD_ATTACK_PREF addr SSHGUARD_ATTACK_SUFF
    | SSHGUARD_BLOCK_PREF addr SSHGUARD_BLOCK_SUFF
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
   SENDMAIL_RELAYDENIED_PREF addr SENDMAIL_RELAYDENIED_SUFF
   | SENDMAIL_AUTHFAILURE_PREF addr SENDMAIL_AUTHFAILURE_SUFF;
   ;

postfixmsg:
    POSTFIX_SASL_LOGINERR_PREF addr POSTFIX_SASL_LOGINERR_SUFF |
    POSTFIX_NO_AUTH_PREF addr ']';

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

/* attack rules for cockpit */
cockpitmsg:
    COCKPIT_AUTHFAIL_PREF addr COCKPIT_AUTHFAIL_SUFF
    ;

/* attack rules for HTTP 401 Unauhtorized in common log format */
clfunauhtdmsg:
    addr CLF_UNAUTHOIRIZED_PREF CLF_UNAUTHOIRIZED_SUFF
    ;

/* attack rules for probes for common web services */
clfwebprobesmsg:
    addr CLF_REQUEST_PREF CLFWEBPROBES_BOTSEARCH_SUFF
    ;

/* attack rules against WordPress */
clfwordpressmsg:
    addr CLF_REQUEST_PREF CLF_WORDPRESS_SUFF
    ;

%%

static void yyerror(__attribute__((unused)) attack_t *a,
    __attribute__((unused)) const char *s) { /* do nothing */ }

int parse_line(char *str, attack_t *attack) {

    /* TODO: reduce danger for SERVICES_CLF_PROBES */
    attack->dangerousness = DEFAULT_ATTACKS_DANGEROUSNESS;

    scanner_init(str);
    int ret = yyparse(attack);
    scanner_fin();

    return ret;
}
