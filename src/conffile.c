// vim: set expandtab tabstop=4 softtabstop=4 shiftwidth=4:
/*
 * tio - a simple TTY terminal I/O application
 *
 * Copyright (c) 2020  Liam Beguin
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
#define _GNU_SOURCE
#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <limits.h>
#include <regex.h>
#include <ini.h>
#include "tio/conffile.h"
#include "tio/options.h"
#include "tio/error.h"
#include "tio/print.h"

static const char *conf = "~/.tiorc";
static struct conf_data *d;

static int get_match(const char *input, const char *pattern, char *match)
{
    int ret;
    int len = 0;
    regex_t re;
    regmatch_t m[2];
    char err[128];

    ret = regcomp(&re, pattern, REG_EXTENDED);
    if (ret) {
        regerror(ret, &re, err, sizeof(err));
        printf("reg error: %s\n", err);
        return ret;
    }

    ret = regexec(&re, input, 2, m, 0);
    if (!ret)
        len = m[1].rm_eo - m[1].rm_so;

    regfree(&re);

    if (len)
        asprintf(&d->match, "%s", &input[m[1].rm_so]);

    return len;
}

static int data_handler(void *user, const char *section, const char *name,
                   const char *value)
{
    if (strcmp(section, d->section_name))
        return 0;

    if (!strcmp(name, "tty")) {
        asprintf(&d->tty, value, d->match);
        option.tty_device = d->tty;
    } else if (!strcmp(name, "baudrate")) {
        option.baudrate = string_to_long((char *)value);
    } else if (!strcmp(name, "databits")) {
        option.databits = atoi(value);
    } else if (!strcmp(name, "flow")) {
        asprintf(&d->flow, "%s", value);
        option.flow = d->flow;
    } else if (!strcmp(name, "stopbits")) {
        option.stopbits = atoi(value);
    } else if (!strcmp(name, "parity")) {
        asprintf(&d->parity, "%s", value);
        option.parity = d->parity;
    } else if (!strcmp(name, "output-delay")) {
        option.output_delay = atoi(value);
    } else if (!strcmp(name, "no-autoconnect")) {
        option.no_autoconnect = atoi(value);
    } else if (!strcmp(name, "log")) {
        option.log = atoi(value);
    } else if (!strcmp(name, "local-echo")) {
        option.local_echo = atoi(value);
    } else if (!strcmp(name, "timestamp")) {
        option.timestamp = atoi(value);
    } else if (!strcmp(name, "log-filename")) {
        asprintf(&d->log_filename, "%s", value);
        option.log_filename = d->log_filename;
    } else if (!strcmp(name, "map")) {
        asprintf(&d->map, "%s", value);
        option.map = d->map;
    } else {
        return 0;
    }

    return 1;
}

static int section_search_handler(void *user, const char *section, const char
                                  *varname, const char *varval)
{
    if (!strcmp(varname, "pattern") && !strcmp(varval, d->user)) {
        asprintf(&d->section_name, "%s", section);
    } else if (!strcmp(varname, "pattern") &&
               get_match(d->user, varval, d->match) > 0) {
        asprintf(&d->section_name, "%s", section);
    } else {
        /* not found */
        return 0;
    }
    return 1;
}

void conf_parse_file(const int argc, char *argv[])
{
    int ret;
    int i;

    d = malloc(sizeof(struct conf_data));
    memset(d, 0, sizeof(struct conf_data));

    if (conf[0] == '~') {
        asprintf(&d->path, "%s%s", getenv("HOME"), &conf[1]);
        conf = d->path;
    }

    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            d->user = argv[i];
            break;
        }
    }

    if (!d->user)
            return;

    ret = ini_parse(conf, section_search_handler, NULL);
    if (!d->section_name) {
        debug_printf("unable to match user input to configuration section (%d)\n", ret);
        return;
    }

    ret = ini_parse(conf, data_handler, NULL);
    if (ret < 0) {
        fprintf(stderr, "Error: unable to parse configuration file (%d)\n", ret);
        exit(EXIT_FAILURE);
    }
}

void conf_exit(void)
{
    free(d->tty);
    free(d->flow);
    free(d->parity);
    free(d->log_filename);
    free(d->map);

    free(d->match);
    free(d->section_name);
    free(d->path);

    free(d);
}
