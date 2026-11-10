/* SPDX-License-Identifier: ISC */
/* Tests use a private hosts.allow, never the system configuration. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char test_hosts_path[64];
#define HOSTSFILE_PATH test_hosts_path
#define main hosts_backend_main
#include "hosts.c"
#undef main

static void expect_file(const char *rules) {
    char actual[4096], expected[4096];
    FILE *file = fopen(test_hosts_path, "r");
    assert(file != NULL);
    size_t size = fread(actual, 1, sizeof(actual) - 1, file);
    assert(!ferror(file));
    actual[size] = '\0';
    fclose(file);
    snprintf(expected, sizeof(expected), "%s%s%s# retained\n",
             HOSTS_SSHGUARD_PREFIX, rules, HOSTS_SSHGUARD_SUFFIX);
    assert(strcmp(actual, expected) == 0);
}

static void block(const char *addr, const char *kind, const char *prefix) {
    attack_t attack;
    unsigned int subnet;
    assert(fill_attack(&attack, &subnet, addr, kind, prefix));
    assert(fw_block(&attack, subnet) == FWALL_OK);
}

static void release(const char *addr, const char *kind, const char *prefix) {
    attack_t attack;
    unsigned int subnet;
    assert(fill_attack(&attack, &subnet, addr, kind, prefix));
    assert(fw_release(&attack, subnet) == FWALL_OK);
}

int main(void) {
    char directory[] = "/tmp/sshg-hosts-XXXXXX";
    attack_t attack;
    unsigned int subnet;
    assert(mkdtemp(directory) != NULL);
    snprintf(test_hosts_path, sizeof(test_hosts_path), "%s/hosts", directory);
    FILE *file = fopen(test_hosts_path, "w");
    assert(file != NULL);
    assert(fputs("# retained\n", file) >= 0);
    assert(fclose(file) == 0);
    assert(fw_init() == FWALL_OK);
    expect_file("");

    block("192.0.2.4", "4", "32");
    block("2001:db8::1", "6", "128");
    expect_file("ALL : 192.0.2.4 [2001:db8::1] : DENY\n");
    release("192.0.2.4", "4", "32");
    release("2001:0db8:0:0:0:0:0:1", "6", "128");
    expect_file("");

    block("192.0.2.47", "4", "24");
    block("2001:db8::beef", "6", "115");
    expect_file("ALL : 192.0.2.0/255.255.255.0 [2001:db8::a000]/115 : DENY\n");
    release("192.0.2.47", "4", "24");
    release("2001:db8::beef", "6", "115");
    expect_file("");

    block("192.0.2.0", "4", "24");
    block("192.0.2.0", "4", "32");
    release("192.0.2.0", "4", "32");
    expect_file("ALL : 192.0.2.0/255.255.255.0 : DENY\n");
    release("192.0.2.0", "4", "24");
    block("2001:db8::", "6", "64");
    block("2001:db8::", "6", "128");
    release("2001:db8::", "6", "64");
    expect_file("ALL : [2001:db8::] : DENY\n");
    assert(fw_flush() == FWALL_OK);
    expect_file("");

    block("192.0.2.47", "4", "0");
    block("2001:db8::1", "6", "0");
    expect_file("ALL : 0.0.0.0/0.0.0.0 [::]/0 : DENY\n");
    assert(fw_flush() == FWALL_OK);
    block("192.0.2.255", "4", "31");
    block("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "6", "127");
    expect_file("ALL : 192.0.2.254/255.255.255.254 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]/127 : DENY\n");
    assert(fw_flush() == FWALL_OK);

    assert(!fill_attack(&attack, &subnet, "192.0.2.1", "4", NULL));
    assert(!fill_attack(&attack, &subnet, "192.0.2.1", "4", ""));
    assert(!fill_attack(&attack, &subnet, "192.0.2.1", "4", "-1"));
    assert(!fill_attack(&attack, &subnet, "192.0.2.1", "4", "33"));
    assert(!fill_attack(&attack, &subnet, "::1", "6", "129"));
    assert(!fill_attack(&attack, &subnet, "::1", "6", "64junk"));
    assert(!fill_attack(&attack, &subnet, "::1", "6", "999999999999999999999999"));
    assert(!fill_attack(&attack, &subnet, "::1", "4", "32"));
    assert(!fill_attack(&attack, &subnet, "192.0.2.1", "6", "128"));
    assert(!fill_attack(&attack, &subnet, "192.0.2.1", "4junk", "32"));
    assert(!fill_attack(&attack, &subnet, "ALL", "4", "32"));
    assert(!fill_attack(&attack, &subnet, NULL, "4", "32"));
    expect_file("");
    assert(fw_fin() == FWALL_OK);
    file = fopen(test_hosts_path, "r");
    assert(file != NULL);
    char line[32];
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line, "# retained\n") == 0);
    assert(fgetc(file) == EOF);
    fclose(file);
    assert(unlink(test_hosts_path) == 0);
    assert(rmdir(directory) == 0);
    return 0;
}
