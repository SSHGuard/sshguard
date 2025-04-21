#define _GNU_SOURCE // for asprintf on Linux
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "metrics.h"

static FILE *metrics_file;
static bool metrics_do_write = false;

const static int metrics_interval = 60; // seconds

void sigalrm_handler(int sig) {
    metrics_do_write = true;
}

/**
 * If SSHGUARD_STATS_DIR is set, initialize metrics logging.
 */
void metrics_init(const char *name) {
    char *stats_dir = getenv("SSHGUARD_STATS_DIR");
    if (!stats_dir) {
        return;
    }

    char *stats_file_path;
    if (asprintf(&stats_file_path, "%s/sshguard_%s.prom", stats_dir, name) < 0) {
        return;
    }

    metrics_file = fopen(stats_file_path, "w");
    if (metrics_file) {
        signal(SIGALRM, sigalrm_handler);
        alarm(metrics_interval);
        syslog(LOG_INFO, "Writing metrics to %s\n", stats_file_path);
    } else {
        perror("Could not open stats file");
    }

    free(stats_file_path);
}

static bool do_metrics() {
    return metrics_do_write && metrics_file;
}

bool metrics_begin() {
    if (!do_metrics())
        return false;

    // clear file by reopening it
    metrics_file = freopen(NULL, "w", metrics_file);
    return true;
}

void metrics_write(const char *name, long val) {
    assert(do_metrics());
    fprintf(metrics_file, "sshguard_%s %ld\n", name, val);
}

void metrics_fin() {
    assert(do_metrics());
    metrics_do_write = false;
    alarm(metrics_interval);
    fflush(metrics_file);
}
