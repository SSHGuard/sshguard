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

%{
#include <string.h>
#include <stdlib.h>

#include "attack.h"
#include "attack_parser.h"
%}

%option debug
%option noinput
%option nounput
%option noyywrap

%array

 /* Start Conditions */
 /* for Login services */
%s ssh_notallowed ssh_reversemap ssh_disconnect ssh_badproto ssh_invalid_format ssh_badkex cockpit_authfail proxmoxve_authfail
 /* for SSHGuard */
%s sshguard_attack sshguard_block
%s bind
 /* for Mail services */
%s dovecot_loginerr cyrusimap_loginerr exim_esmtp_autherr exim_esmtp_loginerr sendmail_relaydenied sendmail_authfailure postfix_loginerr postfix_nonsmtp postfix_greylist opensmtpd_failedcmd postscreen
 /* for FTP services */
%s freebsdftpd_loginerr  proftpd_loginerr  pureftpd_loginerr vsftpd_loginerr
 /* for git services */
%s gitea_autherr

MONTH       (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
MONTHNO     0[0-9]|1[0-2]
DAYNO       [0-9][0-9]?
HOUR        (0|1)[0-9]|2[0-4]
MINPS       [0-5][0-9]
SECONDFRAC  [0-5][0-9]([.,][0-9]+)?
WORD        [a-zA-Z0-9][-_a-zA-Z0-9]+
NUMBER      [0-9]*
FILENAME    [a-zA-Z0-9\/.-]+
YEAR        (1|2)[0-9]{3}
TIMEZONE    Z|[-+]{HOUR}(:?{MINPS})?

TEXT_PRI            {WORD}"."{WORD}
TIMESTAMP_SYSLOG    {MONTH}\ +{DAYNO}\ +{HOUR}:{MINPS}:{MINPS}
TIMESTAMP_TAI64     [0-9A-Fa-f]{24}
SOLARIS_MSGID_TAG   "[ID "[0-9]+" "{TEXT_PRI}"]"
TIMESTAMP_ISO8601   {YEAR}-{MONTHNO}-{DAYNO}(T|" "){HOUR}:?{MINPS}:?{SECONDFRAC}{TIMEZONE}?
RFC5234_HEADER      "<"{NUMBER}">"{NUMBER}
TIMESTAMP_LOCAL     {DAYNO}"/"{MONTH}"/"{YEAR}":"{HOUR}":"{MINPS}":"{MINPS}" "{TIMEZONE}
TIMESTAMP_YMD_HMS   {YEAR}"/"{MONTHNO}"/"{DAYNO}" "{HOUR}":"{MINPS}":"{MINPS}

COLOR_CODE          \x1b"["[0-9;]+"m"

 /* Mon Jan 01 21:00:00 2010 */
TIMESTAMP_DM24H_Y   (Mon|Tue|Wed|Thu|Fri|Sat|Sun)\ {MONTH}\ {DAYNO}\ [0-9:]{8}\ {YEAR}

 /* all words but "sshguard" provided that posix regex don't support negation nor intersection:
  * 1) all words of 2 to 7 characters or 8-* chars
  * 2) words of 7 chars different to "sshguard" (^s.* | s^s.* | ss^h.*
  */
PROCESSNAME ([-_a-zA-Z0-9]{2,7})|([-_a-zA-Z0-9]{9,})|([-_a-rt-zA-RT-Z0-9][-_a-zA-Z0-9]{7})|([sS][-_a-rt-zA-RT-Z0-9][-_a-zA-Z0-9]{6})|([sS]{2}[-_a-gi-zA-gI-Z0-9][-_a-zA-Z0-9]{5})|([sS]{2}[hH][-_a-fh-zA-FH-Z0-9][-_a-zA-Z0-9]{4})|([sS]{2}[hH][gG][-_a-tv-zA-TV-Z0-9][-_a-zA-Z0-9]{3})|([sS]{2}[hH][gG][uU][b-zB-Z0-9][-_a-zA-Z0-9]{2})|([sS]{2}[hH][gG][uU][-_aA][-_a-qs-zA-QS-Z0-9][-_a-zA-Z0-9])|([sS]{2}[hH][gG][uU][-_aA][rR][-_a-ce-zA-CE-Z0-9])

 /* IPv4 address (used in IPv6 address too, for IPv4 encapsulation) */
IPV4        ((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)){3})
 /* IPv6 addresses including compressed variants (RFC 2373) */
IPV6        (::|:(:[0-9a-fA-F]{1,4}){1,7}|[0-9a-fA-F]{1,4}:([0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,5}|(:[0-9a-fA-F]{1,4}){1,6})|([0-9a-fA-F]{1,4}:){3}([0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,3}|(:[0-9a-fA-F]{1,4}){1,4})|([0-9a-fA-F]{1,4}:){5}([0-9a-fA-F]{1,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{1,4}|(:[0-9a-fA-F]{1,4}){1,2})|([0-9a-fA-F]{1,4}:){1,7}:)
 /* an IPv4 packed in IPv6 as IPv4-mapped IPv6 address */
IPV4MAPPED6 ((:(:0{1,4}){0,4}|0{1,4}:(:0{1,4}){1,3}|(0{1,4}:){2}(0{1,4}:0{0,4}:0{1,4}|(:0{1,4}){1,2})|(0{1,4}:){1,4}):[fF]{4}:(((2[0-4]|1[0-9]|[1-9])?[0-9]|25[0-5])\.){3}((2[0-4]|1[0-9]|[1-9])?[0-9]|25[0-5]))

KEY_ALGORITHM    (?i:(RSA|DSA|ECDSA|ED25519))
KEY_FINGERPRINT  (?i:(MD5|SHA256)((:[a-f0-9]{2}){16}|:[0-9a-z+\/]{43}))

HOSTNAME    ([-a-zA-Z0-9]+\.)+[-a-zA-Z0-9]+
HOSTADDR    {HOSTNAME}|{IPV4}|{IPV6}|{IPV4MAPPED6}
FACLEVEL    (<[a-zA-Z0-9]+\.[a-zA-Z0-9]+>)

HTTP_REQUEST    (GET|HEAD|PUT|POST|DELETE)
HTTP_VERSION    HTTP"/"[0-9]("."[0-9])?

 // host part of a hostname (without any domain parts)
SYSLOG_HOSTNAME   {WORD}

 // timestamp (optional PRI) hostname
SYSLOG_HEADER     ({TIMESTAMP_SYSLOG}|{TIMESTAMP_ISO8601})[ ]+{FACLEVEL}?[ ]*{SYSLOG_HOSTNAME}[ ]+

 // identifies process
SYSLOG_TAG        {PROCESSNAME}("/"{PROCESSNAME}){0,2}
SYSLOG_PID        "["{NUMBER}"]"

 /* Common configuration for http botsearch
  * Adapted from fail2ban botsearch filters & tweaked by alip☮exherbo.org,
  * Original author: Frantisek Sumsal
  */
HTTP_BOTSEARCH_WEBMAIL     roundcube|(ext)?mail|horde|(v-?)?webmail
HTTP_BOTSEARCH_PHPMYADMIN  (typo3"/"|xampp"/"|admin"/")?(pma|(php)?[Mm]y[Aa]dmin)
HTTP_BOTSEARCH_WORDPRESS   wp-(admin|config|login|signup)"."php
HTTP_BOTSEARCH_JOOMLA      ("administrator/")?"index.php?option=com_"
HTTP_BOTSEARCH             .*("/"{HTTP_BOTSEARCH_WEBMAIL}|{HTTP_BOTSEARCH_PHPMYADMIN}|{HTTP_BOTSEARCH_WORDPRESS}|{HTTP_BOTSEARCH_JOOMLA}|cgi-bin|mysqladmin)[^,]*

WORDPRESS_LOGIN            "/wp-login"(\.php)?
TYPO3_LOGIN                "/typo3/?loginProvider="
CONTAO_LOGIN               "/contao/login?_hash="
HTTP_LOGIN_200OK_BAD       .*({WORDPRESS_LOGIN}|{TYPO3_LOGIN}|{CONTAO_LOGIN}).*
%%


 /*
  * syslog banner, eg "Nov 22 09:58:58 freyja sshd[94637]: "
  * tokenized as: timestamp hostname procname(subname) [pid]:
  *  both the subname and pid parts can be missing
  */

 /* handle entries with PID and without PID from processes other than sshguard */
{SYSLOG_HEADER}{SYSLOG_TAG}{SYSLOG_PID}:?" "{SOLARIS_MSGID_TAG}? return SYSLOG_BANNER;

{SYSLOG_HEADER}{SYSLOG_TAG}":" return SYSLOG_BANNER;

 /*
  * Busybox syslog banner
  * timestamp (optional host) (optional priority) tag:
  */
({TIMESTAMP_SYSLOG}|{TIMESTAMP_ISO8601})" "({SYSLOG_HOSTNAME}" ")?({TEXT_PRI}" ")?{SYSLOG_TAG}{SYSLOG_PID}":" return BUSYBOX_SYSLOG_BANNER;

 /* RFC 5424 banner */
{RFC5234_HEADER}" "{TIMESTAMP_ISO8601}" "{HOSTNAME}" "{PROCESSNAME}" "{NUMBER}" - - " { return RFC_5234_BANNER; }

 /* metalog banner */
{TIMESTAMP_SYSLOG}" ["{SYSLOG_TAG}"] " return METALOG_BANNER;

 /* socklog banner */
({TIMESTAMP_ISO8601}" ")?{TEXT_PRI}": "({TIMESTAMP_SYSLOG}" ")?({SYSLOG_TAG}{SYSLOG_PID}":")? return SOCKLOG_BANNER;

 /* SSH: invalid or rejected user (cross platform [generated by openssh]) */
"Disconnecting "[Ii]"nvalid user "[^ ]+" "                      { return SSH_INVALUSERPREF; }
"Failed password for "?[Ii]"nvalid user ".+" from "             { return SSH_INVALUSERPREF; }
 /* match disallowed user (not in AllowUsers/AllowGroups or in DenyUsers/DenyGroups) on Linux Ubuntu/FreeBSD */
 /* "User tinydns from 1.2.3.4 not allowed because not listed in AllowUsers" */
"User ".+" from "                                               { BEGIN(ssh_notallowed); return SSH_NOTALLOWEDPREF; }
<ssh_notallowed>" not allowed because ".+                       { BEGIN(INITIAL); return SSH_NOTALLOWEDSUFF; }
 /* match disallowed user root (with PermitRootLogin = no) */
 /* "ROOT LOGIN REFUSED FROM 1.2.3.4" */
"ROOT LOGIN REFUSED FROM "                                      { BEGIN(ssh_notallowed); return SSH_NOTALLOWEDPREF; }

"error: "?"maximum authentication attempts exceeded for".*"from" { return SSH_MAXAUTH; }

"port "{NUMBER}" ssh"?." [preauth]"?(": "{KEY_ALGORITHM}" "{KEY_FINGERPRINT})? { return SSH_ADDR_SUFF; }
"port "{NUMBER}": Change of username or service not allowed".*" [preauth]"?  { return SSH_ADDR_SUFF; }

 /* Solaris-own */
"Failed none for <invalid username> from "                      { BEGIN(ssh_notallowed); return SSH_NOTALLOWEDPREF; }
<ssh_notallowed>" port ".+                                      { BEGIN(INITIAL); return SSH_NOTALLOWEDSUFF; }

 /* get this instead: match invalid login @ Linux Ubuntu */
 /* "Failed password for validuser from 1.2.3.4 port 54609 ssh2" */
"Failed "[^ ]+" for "[^ ]+" from "                              { return SSH_LOGINERR_PREF; }

 /* wrong password for valid user @ FreeBSD, Debian */
"error: PAM: "(([aA]"uthentication "(error|failure))|"unknown user")" for "("illegal user ")?.+" from "            { return SSH_LOGINERR_PAM; }
"via ".*                                                        { return SSH_VIA; }

 /* SSH: connections open and closed without auth attempts */
"Did not receive identification string from "                   { return SSH_NOIDENTIFSTR; }
"Disconnected from "(("invalid"|"authenticating")" user "[^ ]+" ")?               { BEGIN(ssh_disconnect); return SSH_DISCONNECT_PREF; }
"Connection "(closed|reset)" by "(("invalid"|"authenticating")" user "[^ ]+" ")?  { BEGIN(ssh_disconnect); return SSH_CONNECTION_CLOSED; }
<ssh_disconnect>[: ].*"[preauth]"                               { BEGIN(INITIAL); return SSH_PREAUTH_SUFF; }

 /* SSH: clients connecting with other application protocols */
"Bad protocol version identification".*" from "                 { BEGIN(ssh_badproto); return SSH_BADPROTOCOLIDENTIF; }
<ssh_badproto>[ \n].*                                           { BEGIN(INITIAL); return SSH_BADPROTOCOLIDENTIF_SUFF; }

"banner exchange: Connection from "                             { BEGIN(ssh_invalid_format); return SSH_INVALIDFORMAT_PREF; }
<ssh_invalid_format>(" port ".*)[: ]"invalid format"            { BEGIN(INITIAL); return SSH_INVALIDFORMAT_SUFF; }

"fatal: "?"Unable to negotiate with "                                     { BEGIN(ssh_badkex); return SSH_BADKEX_PREF; }
<ssh_badkex>(" port ".*)?[: ].*"no matching ".*" found".*       { BEGIN(INITIAL); return SSH_BADKEX_SUFF; }

[Bb]"ad "("PAM ")?"password attempt for "[^ ]+" from "                      { return DROPBEAR_BAD_PASSWORD; }
[Ll]"ogin attempt for nonexistent user from"                     { return DROPBEAR_BAD_USER; }
[Ee]"xit before auth from <"                                     { return DROPBEAR_EXIT_BEFORE_AUTH_PREF; }
">:".*                                                           { return DROPBEAR_EXIT_BEFORE_AUTH_SUFF; }


 /* SSHGuard */
"Attack from \""                                                { BEGIN(sshguard_attack); return SSHGUARD_ATTACK_PREF; }
<sshguard_attack>"\" on service "{NUMBER}" with danger "{NUMBER}"."    { BEGIN(INITIAL); return SSHGUARD_ATTACK_SUFF; }
"Blocking \""                                                   { BEGIN(sshguard_block); return SSHGUARD_BLOCK_PREF; }
<sshguard_block>"/"{NUMBER}"\" for "{NUMBER}" secs ("{NUMBER}" attacks in "{NUMBER}" secs,".+  { BEGIN(INITIAL); return SSHGUARD_BLOCK_SUFF; }

 /* BIND */
"client @"{WORD}" "                                             { BEGIN(bind); return BIND_PREF; }
<bind>"#".*"query".*"denied".*                                  { BEGIN(INITIAL); return BIND_QUERY_DENIED; }

 /* Cucipop */
"authentication failure "[^0-9]+                                { return CUCIPOP_AUTHFAIL; }

 /* Exim */
({WORD}" ")?"authenticator failed for ".+" ["                   { BEGIN(exim_esmtp_autherr); return EXIM_ESMTP_AUTHFAIL_PREF; }
<exim_esmtp_autherr>"]"(:{NUMBER})?(" I=".+)?(" U=".+)?": 535 Incorrect authentication data"(" (set_id=".+")")?    { BEGIN(INITIAL); return EXIM_ESMTP_AUTHFAIL_SUFF; }

"SMTP protocol error in \"AUTH LOGIN\" H="({HOSTNAME}" ")?"(".*") ["              { BEGIN(exim_esmtp_loginerr); return EXIM_ESMTP_LOGINFAIL_PREF; }
<exim_esmtp_loginerr>"] "("AUTH command used when not advertised"|"LOGIN authentication mechanism not supported")  { BEGIN(INITIAL); return EXIM_ESMTP_LOGINFAIL_SUFF; }

 /* Sendmail */
"Relaying denied. IP name lookup failed ["                      { BEGIN(sendmail_relaydenied); return SENDMAIL_RELAYDENIED_PREF; }
<sendmail_relaydenied>"]"                                       { BEGIN(INITIAL); return SENDMAIL_RELAYDENIED_SUFF; }

 /* Sendmail */
[A-Za-z0-9]+": AUTH failure ("[A-Za-z0-9-]+"): ".+"relay=".*"[" { BEGIN(sendmail_authfailure); return SENDMAIL_AUTHFAILURE_PREF; }
<sendmail_authfailure>"]".*                                     { BEGIN(INITIAL); return SENDMAIL_AUTHFAILURE_SUFF; }

 /* dovecot */
("(libdovecot."[0-9\.]+".dylib) ")?(imap|pop3|submission)"-login: ""Info: "?("Aborted login"|Disconnected).*" (auth failed, "{NUMBER}" attempts".*"): ".+" rip=" { BEGIN(dovecot_loginerr); return DOVECOT_IMAP_LOGINERR_PREF; }
<dovecot_loginerr>", lip=".+                                        { BEGIN(INITIAL); return DOVECOT_IMAP_LOGINERR_SUFF; }
"pam_unix(dovecot:auth): "?"authentication failure; logname= uid=0 euid=0 tty=".*" ruser=".*" rhost=" { return DOVECOT_IMAP_LOGINERR_PAM; }

 /* UWimap login errors */
"Login failed user="[^ ]+" auth="[^ ]*" host="[^ ]+" "          { return UWIMAP_LOGINERR; }

 /* cyrus-imap login error */
"badlogin: "[^\[]*"["                                           { BEGIN(cyrusimap_loginerr); return CYRUSIMAP_SASL_LOGINERR_PREF; }
<cyrusimap_loginerr>"] ".*"SASL".*"fail".*$                     { BEGIN(INITIAL); return CYRUSIMAP_SASL_LOGINERR_SUFF; }

 /* postfix */
"warning: unknown["                                             { BEGIN(postfix_loginerr); return POSTFIX_SASL_LOGINERR_PREF; }
<postfix_loginerr>": SASL "[-A-Z0-9]+" authentication fail".*   { BEGIN(INITIAL); return POSTFIX_SASL_LOGINERR_SUFF; }
"lost connection after "("AUTH"|"CONNECT")" from ".*"["         { return POSTFIX_NO_AUTH_PREF; }
 /* non-SMTP on an SMTP port suggests port-scanning activity */
"warning: non-SMTP command from unknown["                       { BEGIN(postfix_nonsmtp); return POSTFIX_NONSMTP; }
<postfix_nonsmtp>":".*                                          { BEGIN(INITIAL); return POSTFIX_NONSMTP_SUFF; }

"action=greylist".*"client_address="                            { BEGIN(postfix_greylist); return POSTFIX_GREYLIST; }
<postfix_greylist>",".*                                         { BEGIN(INITIAL); return POSTFIX_GREYLIST_SUFF; }

"PREGREET".*"["                                                 { BEGIN(postscreen); return POSTSCREEN_PREF; }
"DNSBL".*"["                                                    { BEGIN(postscreen); return POSTSCREEN_PREF; }
"HANGUP".*"["                                                   { BEGIN(postscreen); return POSTSCREEN_PREF; }
<postscreen>":".*                                               { BEGIN(INITIAL); return POSTSCREEN_SUFF; }

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
"pure-ftpd: "?"("("?"|{SYSLOG_HOSTNAME})"@"                     { BEGIN(pureftpd_loginerr); return PUREFTPD_LOGINERR_PREF; }
<pureftpd_loginerr>") [WARNING] Authentication failed for user ".+  { BEGIN(INITIAL); return PUREFTPD_LOGINERR_SUFF; }

 /* vsftpd */
.+"FAIL LOGIN: Client \""                                       { BEGIN(vsftpd_loginerr); return VSFTPD_LOGINERR_PREF; }
<vsftpd_loginerr>"\""                                           { BEGIN(INITIAL); return VSFTPD_LOGINERR_SUFF; }

 /* cockpit */
"pam_unix(cockpit:auth): "?"authentication failure; logname= uid=0 euid=0 tty= ruser= rhost="  { BEGIN(cockpit_authfail); return COCKPIT_AUTHFAIL_PREF; }
<cockpit_authfail>" "+"user=".+                                    { BEGIN(INITIAL); return COCKPIT_AUTHFAIL_SUFF; }


 /* CLF {{{ */
"["({TIMESTAMP_LOCAL}|{TIMESTAMP_ISO8601})"]" return CLF_TIMESTAMP;

 /* HTTP probes for common web services. */
"\""{HTTP_REQUEST}" "{HTTP_BOTSEARCH}" "{HTTP_VERSION}"\"" { return CLF_WEB_PROBE; }

 /* Bad login URLs.
    HTTP 200 OK responses via POST are failed requests */
" \"POST "{HTTP_LOGIN_200OK_BAD}" "{HTTP_VERSION}"\"" { return CLF_CMS_LOGIN; }

"("[0-9]+(.[0.-9]+)")" return CLF_SUFFIX;

 /* }}} */

 /* OpenSMTPD. */
 /* Unsupported command when attempting to log in. */
[a-z0-9]+" smtp event=failed-command address="                  { BEGIN(opensmtpd_failedcmd); return OPENSMTPD_FAILED_CMD_PREF; }
<opensmtpd_failedcmd>"host="{HOSTNAME}" command=\"".+"\" result=\"503 5.5.1 Invalid command: Command not supported\"" { BEGIN(INITIAL); return OPENSMTPD_UNSUPPORTED_CMD_SUFF; }
 /* Bad credentials */
<opensmtpd_failedcmd>"host="{HOSTNAME}" command=\"AUTH ".+"\" result=\"535 Authentication failed\"" { BEGIN(INITIAL); return OPENSMTPD_AUTHFAIL_SUFF; }

 /* Courier IMAP/POP */
"LOGIN FAILED, "(user|method)=[^ ,]+", ip="                     { return COURIER_AUTHFAIL_PREF; }

 /* OpenVPN */
":"{NUMBER}" TLS Error: TLS handshake failed"                   { return OPENVPN_TLS_ERR_SUFF; }

 /* Gitea - also with color codes */
(({COLOR_CODE})?{TIMESTAMP_YMD_HMS}" "({COLOR_CODE})?)?(({COLOR_CODE})?[a-zA-Z0-9\:\(\)\/\.]*({COLOR_CODE}[^[]*{COLOR_CODE})?" ")?(({COLOR_CODE})?"["[A-Z]"]"({COLOR_CODE})?" ")?("["({COLOR_CODE})?[0-9a-f]*({COLOR_CODE})?"] ")?"Failed authentication attempt for "({COLOR_CODE})?.*({COLOR_CODE})?" from "({COLOR_CODE})?  { BEGIN(gitea_autherr); return GITEA_ERR_PREF; }
<gitea_autherr>(":"[0-9]{1,5}({COLOR_CODE})?":".*)?({COLOR_CODE})?  { BEGIN(INITIAL); return GITEA_ERR_SUFF; }

 /* OpenVPN Portshare */
{TIMESTAMP_ISO8601}" \[stdout#info\] \[OVPN "[0-9]+"\] OUT: \'"{TIMESTAMP_DM24H_Y}" "         { return OPENVPN_PS_TERM_PREF; }
":"{NUMBER}" SIGTERM\[soft,port-share-redirect\] received, client-instance exiting\'" { return OPENVPN_PS_TERM_SUFF; }

 /* MSSQL Failed login */
"Login failed for user \'"{WORD}"\'. Reason: Password did not match that for the login provided. [CLIENT: "        { return MSSQL_AUTHFAIL_PREF; }
"Login failed for user \'"{WORD}"\'. Reason: Could not find a login matching the name provided. [CLIENT: "         { return MSSQL_AUTHFAIL_PREF; }
"Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. [CLIENT: " { return MSSQL_AUTHFAIL_PREF; }
"Length specified in network packet payload did not match number of bytes read; the connection has been closed. Please contact the vendor of the client library. [CLIENT: " { return MSSQL_AUTHFAIL_PREF; }

 /* Proxmox VE */
 /* failed authentication */
"authentication failure; rhost="  { BEGIN(proxmoxve_authfail); return PROXMOXVE_AUTHFAIL_PREF; }
<proxmoxve_authfail>" "+"user=".+" "+"msg=".+                        { BEGIN(INITIAL); return PROXMOXVE_AUTHFAIL_SUFF; }

 /**         COMMON-USE TOKENS       do not touch these          **/
 /* an IPv4 address */
{IPV4}                                                          { yylval.str = yytext; return IPv4; }
{IPV4MAPPED6}                                                   { yylval.str = strrchr(yytext, ':')+1; return IPv4; }

 /* an IPv6 address */
 /* standard | clouds implied | embedded IPv4 */
{IPV6}                                                          { yylval.str = strdup(yytext); return IPv6; }

 /* an host address (PTR) */
{HOSTADDR}                                                      { yylval.str = yytext; return HOSTADDR; }
{NUMBER}                                                        { yylval.num = (int)strtol(yytext, (char **)NULL, 10); return INTEGER; }
 /* syslog timestamp */
 /*{MONTH}\ +{DAYNO}\ +{HOUR}:{MINPS}:{MINPS}                      { return TIMESTAMP_SYSLOG; }*/
{TIMESTAMP_SYSLOG}                                              { return TIMESTAMP_SYSLOG; }

 /* TAI64 timestamp */
"@"{TIMESTAMP_TAI64}                                            { return AT_TIMESTAMP_TAI64; }
{TIMESTAMP_TAI64}                                               { return TIMESTAMP_TAI64; }

 /* iso8601 timestamp */
{TIMESTAMP_ISO8601}                                             { return TIMESTAMP_ISO8601; }

": "[0-9]+" Time(s)"                                              return REPETITIONS;

 /*[^ :]+:[^ ]+                                                    { return FACILITYPRIORITY; } */
{WORD}                                                          { yylval.str = yytext; return WORD; }

"\""[^"]*"\"" { return STRING; }

[ \n\r\t]+            /* eat blanks */
 /* literals */
 /*\n                                                              { return NEWLINE; } */
.                                                               { return yytext[0]; }

 /**         end of COMMON-USE TOKENS                           **/

%%

void scanner_init(char *str) {
    yy_scan_string(str);
}

void scanner_fin() {
    yy_delete_buffer(YY_CURRENT_BUFFER);
}
