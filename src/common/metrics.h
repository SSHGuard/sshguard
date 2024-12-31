#pragma once

bool metrics_begin();
void metrics_init(const char *name);
void metrics_write(const char *name, long val);
void metrics_fin();
