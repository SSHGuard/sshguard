/**
 * @file
 * Parse and display individual attacks from standard input
 */

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "parser/parser.h"
#include "sshguard_log.h"

static void print_attack(const attack_t *attack) {
    printf("attack from %s on service %d with danger %d with pid %d\n",
            attack->address.value, attack->service,
            attack->dangerousness, attack->source);
}

static void print_usage() {
    fprintf(stderr, "usage: sshg-parser [-h] [-v]\n");
}

int main(int argc, char *argv[]) {
    bool debug = false;
    char buf[1000];
    int flag;

    while ((flag = getopt(argc, argv, "hv")) != -1) {
        switch (flag) {
        case 'h':
            print_usage();
            return 0;
        case 'v':
            debug = true;
        }
    }

    // Initialize necessary subsystems.
    sshguard_log_init(true);
    yydebug = yy_flex_debug = debug;

    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        attack_t attack;
        if (parse_line(0, buf, &attack) == 0) {
            print_attack(&attack);
        }
    }
}
