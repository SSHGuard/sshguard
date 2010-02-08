%{
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


#include "../sshguard_log.h"
#include "../sshguard_procauth.h"

#include "../parser.h"

void yyerror(char *msg);
extern int yylex();

%}

/* %pure-parser */
%start text

%union {
    char *str;
    int num;
}

/* semantic values for tokens */
%token <str> IPv4 IPv6 HOSTADDR WORD
%token <num> INTEGER SYSLOG_BANNER_PID

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

void yyerror(char *msg) { /* do nothing */ }


