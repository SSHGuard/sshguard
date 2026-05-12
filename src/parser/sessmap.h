/*
 * Copyright (c) 2026 Ilya Voronin <ivoronin@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include <stdbool.h>

#include "address.h"
#include "attack.h"

/*
 * Per-service session table: maps a (service, sid) pair to a source address.
 * Used when a service splits the IP and the auth-failure event across
 * multiple log lines correlated by a session id (e.g. modern OpenSMTPD).
 * The service code keeps session ids from different services in separate
 * namespaces so a string collision between two services does not matter.
 */
void sessmap_put(enum service service, const char *sid, const sshg_address_t *addr);
bool sessmap_get(enum service service, const char *sid, sshg_address_t *out);
void sessmap_del(enum service service, const char *sid);
