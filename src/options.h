/*
 * options.h - Define the interface for parsing SS_PLUGIN_OPTIONS
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the simple-obfs.
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

#ifndef _OPTIONS_H
#define _OPTIONS_H

#define MAX_OPTION_NUM 16

typedef struct options {
    size_t num;
    char *keys[MAX_OPTION_NUM];
    char *values[MAX_OPTION_NUM];
} options_t;

int parse_options(char *str, size_t str_len, options_t *opts);
const char *get_opt(const char *key, options_t *opts);

#endif // _OPTIONS_H
