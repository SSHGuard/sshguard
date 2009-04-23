%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sshguard_log.h"
#include "sshguard_procauth.h"

#include "parser.h"

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
%token SYSLOG_BANNER TIMESTAMP_SYSLOG TIMESTAMP_TAI64 FACILITYPRIORITY METALOG_BANNER
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
/* FreeBSD's FTPd */
%token FREEBSDFTPD_LOGINERR_PREF FREEBSDFTPD_LOGINERR_SUFF
/* proFTPd */
%token PROFTPD_LOGINERR_PREF PROFTPD_LOGINERR_SUFF
/* PureFTPd */
%token PUREFTPD_LOGINERR_PREF PUREFTPD_LOGINERR_SUFF

%%

/* log source */
text:
    syslogent                                       {   YYACCEPT;   }
    | multilogent                                   {   YYACCEPT;   }
    | metalogent                                    {   YYACCEPT;   }
    | logmsg                                        {   YYACCEPT;   }
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
    | freebsdftpdmsg    {   parsed_attack.service = SERVICES_FREEBSDFTPD; }
    | proftpdmsg        {   parsed_attack.service = SERVICES_PROFTPD; }
    | pureftpdmsg       {   parsed_attack.service = SERVICES_PUREFTPD; }
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
                        union { struct in_addr addr4; struct in6_addr addr6; } addr;
                        struct hostent *he;

                        if (1 == 1) {
                            he = gethostbyname($1);
                            if (he == NULL) {
                                /* could not resolve hostname in IPv4! */
                                sshguard_log(LOG_DEBUG, "Could not resolve hostname '%s' in IPv4 address: %s.", $1, hstrerror(h_errno));
                                /* try IPv6 */
                                he = gethostbyname2($1, AF_INET6);
                                if (he == NULL) {
                                    /* could not resolve hostname in IPv6 either! */
                                    sshguard_log(LOG_DEBUG, "Could not resolve hostname '%s' in IPv6 address: %s.", $1, hstrerror(h_errno));
                                    sshguard_log(LOG_ERR, "Could not resolve hostname '%s' in IPv4 nor IPv6 address!", $1);
                                    YYABORT;
                                }
                                /* SUCCESSFULLY resolved IPv6 */
                                /* copy IPv6 address */
                                memcpy(& addr.addr6, he->h_addr_list[0], he->h_length);
                                inet_ntop(AF_INET6, & addr.addr6, parsed_attack.address.value, ADDRLEN);
                                parsed_attack.address.kind = ADDRKIND_IPv6;
                            } else {
                                /* SUCCESSFULLY resolved IPv4 */
                                /* copy IPv4 address */
                                memcpy(& addr.addr4, he->h_addr_list[0], he->h_length);
                                inet_ntop(AF_INET, & addr.addr4, parsed_attack.address.value, ADDRLEN);
                                parsed_attack.address.kind = ADDRKIND_IPv4;
                            }
                            sshguard_log(LOG_DEBUG, "Successfully resolved host '%s' to address '%s'.", $1, parsed_attack.address.value);
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

%%

void yyerror(char *msg) { /* do nothing */ }


