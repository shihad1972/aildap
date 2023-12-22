/*
 *
 *  aildap: collection of ldap utilities
 *  Copyright (C) 2023  Iain M Conochie <iain-AT-ailsatech-DOT-net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  config.c
 *
 *  Configuration function defintions for the ailsa ldap library
 *
 *  Part of the ldap collection suite of program
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <regex.h>
#include <ailsa.h>
#include <ailsaldap.h>

static void
aildap_parse_system_config(AILSA_LIST *config);

static void
aildap_parse_user_config(AILSA_LIST *config, const char *prog);

static void
aildap_parse_config_values(AILSA_LIST *config, FILE *file);

void
aildap_parse_config(AILSA_LIST *config, const char *prog)
{
        aildap_parse_system_config(config);
        aildap_parse_user_config(config, prog);
}

static void
aildap_parse_system_config(AILSA_LIST *config)
{
// Need to add other potential config files
        const char *file = "/etc/ldap/ldap.conf";
        FILE *conf_file = NULL;

        if (!(conf_file = fopen(file, "r"))) {
                ailsa_syslog(LOG_DAEMON, "Cannot open file %s\n", file);
                goto cleanup;
        }
        aildap_parse_config_values(config, conf_file);
        cleanup:
                if (conf_file)
                        fclose(conf_file);
}

static void
aildap_parse_user_config(AILSA_LIST *config, const char *prog)
{
        char file[RBUFF_S];
        FILE *conf = NULL;
        char *home = getenv("HOME");

        if (snprintf(file, RBUFF_S, "%s/.%s/%s.conf", home, PACKAGE, prog) >= RBUFF_S)
                ailsa_syslog(LOG_DAEMON, "Path to user config truncated");
        if (!(conf = fopen(file, "r"))) {
                ailsa_syslog(LOG_DAEMON, "Cannot open file %s\n", file);
                goto cleanup;
        }
        aildap_parse_config_values(config, conf);
        cleanup:
                if(conf)
                        fclose(conf);
}

static void
aildap_parse_config_values(AILSA_LIST *config, FILE *file)
{
        char l[RBUFF_S], k[RBUFF_S], v[RBUFF_S];
        char *p;
        int i, retval,  max = 128;

        for (i=1; max > 0; i++) {
                if (!(fgets(l, RBUFF_S - 1, file))) {
                        break;
                }
                if (sscanf(l, " %[#\n\r]", k))   // Empty line or comment
                        continue;
                if (sscanf(l, " %[a-zA-Z0-9_] %[^#\n\r]", k, v) < 2) {
                        ailsa_syslog(LOG_DAEMON, "error in config file at line %d: %s\n", i, l);
                        continue;
                }
                for (p = k; *p; p++) if (isalpha(*p))*p = tolower(*p);
                if ((retval = add_to_kv_list(config, k, v)) != 0)
                        exit(retval);
                max--;       
        }
        return;
}

