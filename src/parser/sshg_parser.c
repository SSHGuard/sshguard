/**
 * @file
 * Parse and display individual attacks from standard input
 */

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "parser.h"
#include "sandbox.h"

static void print_attack(const attack_t *attack) {
    printf("%d %s %d %d\n", attack->service, attack->address.value,
           attack->address.kind, attack->dangerousness);
}

static void print_usage() {
    fprintf(stderr, "usage: sshg-parser [-adh]\n");
}

int main(int argc, char *argv[]) {
    bool annotate = false, debug = false;
    char buf[1000];
    int flag;

    sandbox_init();

    while ((flag = getopt(argc, argv, "adh")) != -1) {
        switch (flag) {
        case 'a':
            annotate = true;
            break;
        case 'd':
            debug = true;
            break;
        case 'h':
            print_usage();
            return 0;
        case '?':
            print_usage();
            return 1;
        }
    }

    yydebug = yy_flex_debug = debug;

    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        attack_t attack;
        bool is_attack = !parse_line(buf, &attack);
        if (annotate) {
            if (is_attack) {
                fputs("* ", stdout);
            } else {
                fputs("  ", stdout);
            }
            fputs(buf, stdout);
            fflush(stdout);
        } else {
            if (is_attack) {
                print_attack(&attack);
                fflush(stdout);
            }
        }
    }
}
