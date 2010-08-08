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


/* the symbol table definitions */
%{
#include <string.h>
#include <stdlib.h>

#include "attack_parser.h"

#include "../parser.h"


void scanner_init(char *str) {
    yy_scan_string(str);
}

void scanner_fin() {
    yy_delete_buffer(YY_CURRENT_BUFFER);
}

int getsyslogpid(char *syslogbanner, int length) {
    int i;
    syslogbanner[length-2] = '\0';
    for (i = length; syslogbanner[i] != '['; i--);
    return strtol(& syslogbanner[i+1], (char **)NULL, 10);
}

int filtersyslogprocess(char *syslogbanner) {
    int i;
    char *cursor;
    cursor = syslogbanner + strlen("Jan 01 01:01:01 ");
    for (i = 0; cursor[i] != ' '; i++);
    cursor[i] = '\0';
    if (strcmp(cursor, "sshguard") == 0) return 1;
    return 0;
}

%}

%option noyywrap
 /* enable debugging messages if yy_flex_debug != 0 */
%option debug

%array

 /* Start Conditions */
 /* for Login services */
%s ssh_notallowed ssh_loginerr ssh_reversemap
 /* for Mail services */
%s dovecot_loginerr  cyrusimap_loginerr exim_esmtp_autherr sendmail_relaydenied
 /* for FTP services */
%s freebsdftpd_loginerr  proftpd_loginerr  pureftpd_loginerr vsftpd_loginerr


MONTH       (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
DAYNO       [1-9][0-9]?
HOUR        (0|1)[0-9]|2[0-4]
MINPS       [0-5][0-9]
WORD        [a-zA-Z0-9][-_a-zA-Z0-9]+
NUMBER      [1-9][0-9]*
HOSTADDR    localhost|([-a-zA-Z0-9]+\.)+[a-zA-Z]+

TIMESTAMP_SYSLOG    {MONTH}\ +{DAYNO}\ +{HOUR}:{MINPS}:{MINPS}
TIMESTAMP_TAI64     [0-9A-Fa-f]{24}
SOLARIS_MSGID_TAG   "[ID "[0-9]+" "{WORD}"."{WORD}"]"

 /* all words but "sshguard" provided that posix regex don't support negation nor intersection:
  * 1) all words of 2 to 7 characters or 8-* chars
  * 2) words of 7 chars different to "sshguard" (^s.* | s^s.* | ss^h.*
  */
PROCESSNAME ([-_a-zA-Z0-9]{2,7})|([-_a-zA-Z0-9]{9,})|([-_a-rt-zA-RT-Z0-9][-_a-zA-Z0-9]{7})|([sS][-_a-rt-zA-RT-Z0-9][-_a-zA-Z0-9]{6})|([sS]{2}[-_a-gi-zA-gI-Z0-9][-_a-zA-Z0-9]{5})|([sS]{2}[hH][-_a-fh-zA-FH-Z0-9][-_a-zA-Z0-9]{4})|([sS]{2}[hH][gG][-_a-tv-zA-TV-Z0-9][-_a-zA-Z0-9]{3})|([sS]{2}[hH][gG][uU][b-zB-Z0-9][-_a-zA-Z0-9]{2})|([sS]{2}[hH][gG][uU][-_aA][-_a-qs-zA-QS-Z0-9][-_a-zA-Z0-9])|([sS]{2}[hH][gG][uU][-_aA][rR][-_a-ce-zA-CE-Z0-9])

 /* IPv4 address (used in IPv6 address too, for IPv4 encapsulation) */
IPV4        ((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)){3})
 /* IPv6 addresses including compressed variants (RFC 2373) */
IPV6        (::|:(:[0-9A-F]{1,4}){1,7}|[0-9A-F]{1,4}:([0-9A-F]{1,4}:(:[0-9A-F]{1,4}){1,5}|(:[0-9A-F]{1,4}){1,6})|([0-9A-F]{1,4}:){3}([0-9A-F]{1,4}:(:[0-9A-F]{1,4}){1,3}|(:[0-9A-F]{1,4}){1,4})|([0-9A-F]{1,4}:){5}([0-9A-F]{1,4}:[0-9A-F]{0,4}:[0-9A-F]{1,4}|(:[0-9A-F]{1,4}){1,2})|([0-9A-F]{1,4}:){1,7}:)
 /* an IPv4 packed in IPv6 as IPv4-mapped IPv6 address */
IPV4MAPPED6 ((:(:0{1,4}){0,4}|0{1,4}:(:0{1,4}){1,3}|(0{1,4}:){2}(0{1,4}:0{0,4}:0{1,4}|(:0{1,4}){1,2})|(0{1,4}:){1,4}):F{4}:(((2[0-4]|1[0-9]|[1-9])?[0-9]|25[0-5])\.){3}((2[0-4]|1[0-9]|[1-9])?[0-9]|25[0-5]))
%%


 /*
  * syslog banner, eg "Nov 22 09:58:58 freyja sshd[94637]: "
  * tokenized as: timestamp hostname procname(subname) [pid]:
  *  both the subname and pid parts can be missing
  *
  * return SYSLOG_BANNER_PID or SYSLOG_BANNER depending on the presence of [pid]
  */

 /* handle entries with PID and without PID from processes other than sshguard */
{TIMESTAMP_SYSLOG}[ ]+([a-zA-Z0-9]|{WORD}|{HOSTADDR})[ ]+{PROCESSNAME}"["{NUMBER}"]: "{SOLARIS_MSGID_TAG}? {
        /* extract PID */
        yylval.num = getsyslogpid(yytext, yyleng);
        return SYSLOG_BANNER_PID;
        }

{TIMESTAMP_SYSLOG}[ ]+([a-zA-Z0-9]|{WORD}|{HOSTADDR})[ ]+({PROCESSNAME}":")?   { return SYSLOG_BANNER; }

 /* syslog style  "last message repeated N times" */
"last message repeated "([1-9][0-9]*)" times"                   {
                                                                    /* extract number of times */
                                                                    yylval.num = (int)strtol(& yytext[sizeof("last message repeated ")-1], (char **)NULL, 10);
                                                                    return LAST_LINE_REPEATED_N_TIMES;
                                                                }

 /* metalog banner */
{TIMESTAMP_SYSLOG}" ["{PROCESSNAME}"] "                         { return METALOG_BANNER; }


 /* SSH: invalid or rejected user (cross platform [generated by openssh]) */
"Invalid user ".+" from "                         { return SSH_INVALUSERPREF; }
 /* match disallowed user (not in AllowUsers/AllowGroups or in DenyUsers/DenyGroups) on Linux Ubuntu/FreeBSD */
 /* "User tinydns from 1.2.3.4 not allowed because not listed in AllowUsers" */
"User ".+" from "                                               { BEGIN(ssh_notallowed); return SSH_NOTALLOWEDPREF; }
<ssh_notallowed>" not allowed because ".+                       { BEGIN(INITIAL); return SSH_NOTALLOWEDSUFF; }

 /* Solaris-own */
"Failed none for <invalid username> from "                      { BEGIN(ssh_notallowed); return SSH_NOTALLOWEDPREF; }
<ssh_notallowed>" port ".+                                      { BEGIN(INITIAL); return SSH_NOTALLOWEDSUFF; }

 /* get this instead: match invalid login @ Linux Ubuntu */
 /* "Failed password for validuser from 1.2.3.4 port 54609 ssh2" */
"Failed "[^ ]+" for "[^ ]+" from "                              { BEGIN(ssh_loginerr); return SSH_LOGINERR_PREF; }
<ssh_loginerr>"port "{NUMBER}" ssh".?                           { BEGIN(INITIAL); return SSH_LOGINERR_SUFF; }

 /* wrong password for valid user @ FreeBSD, Debian */
"error: PAM: "[aA]"uthentication "(error|failure)" for "("illegal user ")?.+" from "            { return SSH_LOGINERR_PAM; }

 /* SSH: reverse mapping "possible break-in attempt!" */
"reverse mapping checking getaddrinfo for "[^\[]*"["            { BEGIN(ssh_reversemap); return SSH_REVERSEMAP_PREF; }
<ssh_reversemap>"] ".*"POSSIBLE BREAK-IN ATTEMPT!"              { BEGIN(INITIAL); return SSH_REVERSEMAP_SUFF; }

 /* SSH: connections open and closed without auth attempts */
"Did not receive identification string from "                   { return SSH_NOIDENTIFSTR; }

 /* SSH: clients connecting with other application protocols */
"Bad protocol version identification".*" from "                 { return SSH_BADPROTOCOLIDENTIF; }

 /* Cucipop */
"authentication failure "[^0-9]+                                { return CUCIPOP_AUTHFAIL; }

 /* Exim */
.*" auth_plaintext authenticator failed for ".+" ["             { BEGIN(exim_esmtp_autherr); return EXIM_ESMTP_AUTHFAIL_PREF; }
<exim_esmtp_autherr>"]:"[0-9]+" I=".+": 535 Incorrect authentication data (set_id=test)"    { BEGIN(INITIAL); return EXIM_ESMTP_AUTHFAIL_SUFF; }

 /* Sendmail */
"Relaying denied. IP name lookup failed ["                      { BEGIN(sendmail_relaydenied); return SENDMAIL_RELAYDENIED_PREF; }
<sendmail_relaydenied>"]"                                       { BEGIN(INITIAL); return SENDMAIL_RELAYDENIED_SUFF; }

 /* dovecot */
"imap-login: Aborted login (auth failed, "{NUMBER}" attempts): ".+" rip=" { BEGIN(dovecot_loginerr); return DOVECOT_IMAP_LOGINERR_PREF; }
<dovecot_loginerr>", lip=".+                                        { BEGIN(INITIAL); return DOVECOT_IMAP_LOGINERR_SUFF; }

 /* UWimap login errors */
"Login failed user="[^ ]+" auth="[^ ]*" host="[^ ]+" "          { return UWIMAP_LOGINERR; }

 /* cyrus-imap login error */
"badlogin: "[^\[]*"["                                           { BEGIN(cyrusimap_loginerr); return CYRUSIMAP_SASL_LOGINERR_PREF; }
<cyrusimap_loginerr>"] ".*"SASL".*"checkpass failed"            { BEGIN(INITIAL); return CYRUSIMAP_SASL_LOGINERR_SUFF; }

 /* FreeBSD's ftpd login errors */
"FTP LOGIN FAILED FROM "                                        { BEGIN(freebsdftpd_loginerr); return FREEBSDFTPD_LOGINERR_PREF; }
<freebsdftpd_loginerr>", ".+                                    { BEGIN(INITIAL); return FREEBSDFTPD_LOGINERR_SUFF; }

 /* ProFTPd */
{HOSTADDR}" ("[^\[]+"["                                         { BEGIN(proftpd_loginerr); return PROFTPD_LOGINERR_PREF; }
<proftpd_loginerr>"])".*" no such user "("found ")?.+           { BEGIN(INITIAL); return PROFTPD_LOGINERR_SUFF; }
 /* another log entry from ProFTPd */
{HOSTADDR}" ("[[]+"["                                           { BEGIN(proftpd_loginerr); return PROFTPD_LOGINERR_PREF; }
"]) - USER "{WORD}" (Login failed): ".*                         { BEGIN(INITIAL); return PROFTPD_LOGINERR_SUFF; }

 /* Pure-FTPd */
"pure-ftpd: "?"("("?"|{WORD}|{HOSTADDR})"@"                     { BEGIN(pureftpd_loginerr); return PUREFTPD_LOGINERR_PREF; }
<pureftpd_loginerr>") [WARNING] Authentication failed for user ".+  { BEGIN(INITIAL); return PUREFTPD_LOGINERR_SUFF; }

 /* vsftpd */
.+"FAIL LOGIN: Client \""                                       { BEGIN(vsftpd_loginerr); return VSFTPD_LOGINERR_PREF; }
<vsftpd_loginerr>"\""                                           { BEGIN(INITIAL); return VSFTPD_LOGINERR_SUFF; }

 /**         COMMON-USE TOKENS       do not touch these          **/
 /* an IPv4 address */
{IPV4}                                                          { yylval.str = yytext; return IPv4; }
{IPV4MAPPED6}                                                   { yylval.str = strrchr(yytext, ':')+1; return IPv4; }

 /* an IPv6 address */
 /* standard | clouds implied | embedded IPv4 */
{IPV6}                                                          { yylval.str = yytext; return IPv6; }

 /* an host address (PTR) */
{HOSTADDR}                                                      { yylval.str = yytext; return HOSTADDR; }
{NUMBER}                                                        { yylval.num = (int)strtol(yytext, (char **)NULL, 10); return INTEGER; }
 /* syslog timestamp */
 /*{MONTH}\ +{DAYNO}\ +{HOUR}:{MINPS}:{MINPS}                      { return TIMESTAMP_SYSLOG; }*/
{TIMESTAMP_SYSLOG}                                              { return TIMESTAMP_SYSLOG; }

 /* TAI64 timestamp */
"@"{TIMESTAMP_TAI64}                                            { return AT_TIMESTAMP_TAI64; }
{TIMESTAMP_TAI64}                                               { return TIMESTAMP_TAI64; }

 /*[^ :]+:[^ ]+                                                    { return FACILITYPRIORITY; } */
{WORD}                                                          { yylval.str = yytext; return WORD; }
[ \n\t]+            /* eat blanks */
 /* literals */
 /*\n                                                              { return NEWLINE; } */
.                                                               { return yytext[0]; }

 /**         end of COMMON-USE TOKENS                           **/

