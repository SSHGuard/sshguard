#include "attack.h"

struct service_s {
    enum service code;
    const char* name;
};

static const struct service_s services[] = {
    {SERVICES_SSH, "SSH"},
    {SERVICES_SSHGUARD, "SSHGuard"},
    {SERVICES_UWIMAP, "UW IMAP"},
    {SERVICES_DOVECOT, "Dovecot"},
    {SERVICES_CYRUSIMAP, "Cyrus IMAP"},
    {SERVICES_CUCIPOP, "CUCIPOP"},
    {SERVICES_EXIM, "exim"},
    {SERVICES_SENDMAIL, "Sendmail"},
    {SERVICES_POSTFIX, "Postfix"},
    {SERVICES_OPENSMTPD, "OpenSMTPD"},
    {SERVICES_COURIER, "Courier"},
    {SERVICES_FREEBSDFTPD, "FreeBSD FTPD"},
    {SERVICES_PROFTPD, "ProFTPD"},
    {SERVICES_PUREFTPD, "PureFTPD"},
    {SERVICES_VSFTPD, "VSFTPD"},
    {SERVICES_COCKPIT, "Cockpit"},
    {SERVICES_CLF_UNAUTH, "CLF Unauthorized"},
    {SERVICES_CLF_PROBES, "CLF Probes"},
    {SERVICES_CLF_WORDPRESS, "Wordpress"},
    {SERVICES_OPENVPN, "OpenVPN"},
    {SERVICES_GITEA, "Gitea"},
};

const char *service_to_name(enum service code) {
    for (int i = 0; i < sizeof(services)/sizeof(struct service_s); i++) {
        if (code == services[i].code) {
            return services[i].name;
        }
    }
    return "unknown service";
}
