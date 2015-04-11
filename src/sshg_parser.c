#include <stdbool.h>
#include <stdio.h>

#include "parser/parser.h"
#include "sshguard_log.h"
#include "sshguard_procauth.h"

int main() {
    char buf[1000];

    // Initialize necessary subsystems.
    sshguard_log_init(true);
    procauth_init();

    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        if (parse_line(0, buf) == 0) {
            printf("Attack from %s on service %d\n",
                    parsed_attack.address.value, parsed_attack.service);
        }
    }
}
