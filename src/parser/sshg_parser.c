/**
 * @file
 * Parse and display individual attacks from standard input
 */

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "parser/parser.h"

static void print_attack(const attack_t *attack) {
    printf("%d %s %d\n", attack->service, attack->address.value,
           attack->dangerousness);
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
            break;
        case '?':
            print_usage();
            return 1;
        }
    }

    yydebug = yy_flex_debug = debug;

    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        attack_t attack;
        if (parse_line(0, buf, &attack) == 0) {
            print_attack(&attack);
            fflush(stdout);
        }
    }
}
