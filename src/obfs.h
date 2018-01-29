/*
 * obfs.h - Interfaces of obfuscating function
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the simple-obfs.
 *
 * simple-obfs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * simple-obfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with simple-obfs; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef OBFS_H
#define OBFS_H

#include <stdbool.h>
#include "encrypt.h"

#define OBFS_OK         0
#define OBFS_NEED_MORE -1
#define OBFS_ERROR     -2

typedef struct obfs {
    int obfs_stage;
    int deobfs_stage;
    buffer_t *buf;
    void *extra;
} obfs_t;

typedef struct obfs_para {
    const char *name;
    const char *host;
    const char *uri;
    uint16_t port;
    bool send_empty_response_upon_connection;

    int(*const obfs_request)(buffer_t *, size_t, obfs_t *);
    int(*const obfs_response)(buffer_t *, size_t, obfs_t *);
    int(*const deobfs_request)(buffer_t *, size_t, obfs_t *);
    int(*const deobfs_response)(buffer_t *, size_t, obfs_t *);
    int(*const check_obfs)(buffer_t *);
    void(*const disable)(obfs_t *);
    int(*const is_enable)(obfs_t *);
} obfs_para_t;


#endif
