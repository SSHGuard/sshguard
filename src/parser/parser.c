/**
 * @file
 * Parse and display individual attacks from standard input
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "metrics.h"
#include "parser.h"
#include "sandbox.h"

#define MAX_LEN 1000

unsigned int test_counter = 0;

static void print_attack(const attack_t *attack) {
    printf("%d %s %d %d\n", attack->service, attack->address.value,
           attack->address.kind, attack->dangerousness);
}

static void parse_to_buf(char buf[static 1], char dst[static MAX_LEN]) {
    attack_t attack;
    bool is_attack = !parse_line(buf, &attack);
    if (is_attack) {
        snprintf(dst, MAX_LEN,
                "%d %s %d %d\n", attack.service, attack.address.value,
                attack.address.kind, attack.dangerousness);
    } else {
        strncpy(dst, "*\n", MAX_LEN);
    }
}

static void print_usage() {
    fprintf(stderr, "usage: sshg-parser [-adht]\n");
}

static void test_next_line(char buf[static MAX_LEN], unsigned int lineno) {
    static unsigned char state = 0;
    static char expected[MAX_LEN], result[MAX_LEN];
    static bool match;

    if (buf[0] == '\n' || buf[0] == '#') {
        // skip blank lines and comments
        return;
    }

    switch (state) {
        case 0: // line with input
            strncpy(expected, buf, sizeof(expected));
            parse_to_buf(buf, result);
            state++;
            break;
        case 1: // line with expected output
            match = strcmp(buf, result) == 0;
            state++;
            break;
        case 2: // line with type of test
            test_counter += 1;
            if (match) {
                printf("ok %d", test_counter);
            }
            else {
                printf("not ok %d", test_counter);
            }
            switch (buf[0]) {
                case 'M': // expected match
                    if (match) {
                        putchar('\n');
                    } else {
                        printf(" # %u: actual: %s", lineno, result);
                    }
                    break;
                case 'X': // expected fail
                    printf(" # TODO\n");
                    break;
                default:
                    puts("Bail out! Malformed expected test result");
                    exit(99);
            }
            printf("# %s", expected);
            state = 0;
            break;
        default:
            abort();
    }
}

int main(int argc, char *argv[]) {
    bool annotate = false, debug = false, test_mode = false;
    char buf[MAX_LEN];
    int flag;

    init_log();
    metrics_init("parser");
    sandbox_init();

    while ((flag = getopt(argc, argv, "adht")) != -1) {
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
        case 't':
            test_mode = true;
            break;
        case '?':
            print_usage();
            return 1;
        }
    }

    yydebug = yy_flex_debug = debug;

    // Number of input lines read. Used to report line number in test mode,
    // otherwise serves as a counter for total number of logs ingested.
    unsigned int lineno = 0;

    unsigned int attacks_total = 0;
    unsigned int danger_total = 0;
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        lineno++;
        if (test_mode) {
            test_next_line(buf, lineno);
        } else {
            attack_t attack;
            bool is_attack = !parse_line(buf, &attack);
            if (is_attack) {
                attacks_total++;
                danger_total += attack.dangerousness;
            }

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
        if (metrics_begin()) {
            metrics_write("logs_read_total", lineno);
            metrics_write("attacks_total", attacks_total);
            metrics_write("danger_total", danger_total);
            metrics_fin();
        }
    }

    if (test_mode) {
        printf("1..%d\n", test_counter);
    }
}
