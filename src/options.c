/*
 * jconf.c - Parse the JSON format config file
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "options.h"

int
parse_options(char *str, size_t str_len, options_t *opts)
{
    int i, opt_idx;
    char p;

    i = 0;
    opt_idx = 0;
    p = '\0';

    if (str == NULL || str_len == 0) return -1;

    opts->keys[0] = str;

    while (opt_idx < MAX_OPTION_NUM
            && i < str_len && str[i] != '\0') {
        char c = str[i];
        switch (c) {
            case '\\':
                if (i + 1 == str_len) return -1;
                memmove(str + i, str + i + 1, str_len - i - 1);
                str_len--;
                str[str_len] = '\0';
                break;
            case ';':
                if (p != '\\') {
                    str[i] = '\0';
                    if (i + 1 < str_len) {
                        opt_idx++;
                        opts->keys[opt_idx] = str + i + 1;
                    }
                }
                i++;
                break;
            case '=':
                if (p != '\\') {
                    if (i + 1 == str_len) return -1;
                    str[i] = '\0';
                    opts->values[opt_idx] = str + i + 1;
                }
                i++;
                break;
            default:
                i++;
                break;
        }
        p = c;
    }

    opts->num = opt_idx + 1;

    return opts->num;
}

const char*
get_opt(const char *key, options_t *opts)
{
    int i;
    for (i = 0; i < opts->num; i++) {
        if (strcmp(key, opts->keys[i]) == 0) {
            if (opts->values[i] != NULL)
                return opts->values[i];
            else
                return key;
        }
    }
    return NULL;
}
