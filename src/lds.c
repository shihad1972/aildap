/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2013-2014  Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  lds.c:
 * 
 *  Test searching in ldap directory
 * 
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif // HAVE_GETOPT_H
#include <errno.h>
#include <error.h>
#include <syslog.h>
#include <ldap.h>
#include <ailsa.h>
#include <ailsaldap.h>

/*
 * This struct is quite useful, as all the pointers are const and so
 * point to _already existing pointers_ The cool thing about this is
 * they do not need to be free'ed as they exist outside the struct.
 *
 * You will notice in the parse_lds_command_line that we can configure
 * pointers in this struct to point directly at the command line arguments
 * passed to the application.
 */
typedef struct lds_config_s {
        const char *user, *url, *pass, *base_dn, *filter;
} lds_config_s;

static void
fill_lds_config(lds_config_s *config, AILSA_LIST *list);

static void
parse_lds_command_line(int argc, char *argv[], lds_config_s *config);

static void
lds_error(int error);

int
main(int argc, char *argv[])
{
        int retval = 0;
        char *dn = NULL;
        lds_config_s *config = ailsa_calloc(sizeof(lds_config_s), "config in main");
        LDAP *shihad = NULL;
        LDAPMessage *res = NULL;
        LDAPMessage *e = NULL;
        AILSA_LIST *list;

        create_kv_list(&list);
        aildap_parse_config(list, basename(argv[0]));
        fill_lds_config(config, list);
        if (argc > 1)
                parse_lds_command_line(argc, argv, config);
        ailsa_ldap_init(&shihad, config->url);
        if ((retval = ldap_simple_bind_s(shihad, config->user, config->pass)) != LDAP_SUCCESS) {
                fprintf(stderr, "Bind failed with %s\n", ldap_err2string(retval));
		if (shihad)
			ldap_unbind(shihad);
                exit(2);
        }
        if ((retval = ldap_search_s(shihad, config->base_dn, LDAP_SCOPE_SUBTREE, config->filter, NULL, 0, &res)) != LDAP_SUCCESS) {
                fprintf(stderr, "Search failed with %s\n", ldap_err2string(retval));
                if (shihad)
                        ldap_unbind(shihad);
                exit(3);
        }
        printf("We have %d entries\n", ldap_count_entries(shihad, res));
        for (e = ldap_first_entry(shihad, res); e != NULL; e = ldap_next_entry(shihad, e)) {
                dn = ldap_get_dn(shihad, e);
                printf("dn: %s\n", dn);
                free(dn);
                dn = NULL;
        }
        ldap_msgfree(res);
        ldap_unbind(shihad);
        destroy_kv_list(list);
        my_free(config);
        return retval;
}

static void
fill_lds_config(lds_config_s *config, AILSA_LIST *list)
{
        if (!(config->user = get_value_from_kv_list(list, "user")))
                lds_error(CONF_USER);
        if (!(config->url = get_value_from_kv_list(list, "url")))
                lds_error(CONF_URL);
        if (!(config->pass = get_value_from_kv_list(list, "pass")))
                lds_error(CONF_PASS);
        if (!(config->base_dn = get_value_from_kv_list(list, "base")))
                lds_error(CONF_BASE_DN);
        if (!(config->filter = get_value_from_kv_list(list, "filter")))
                lds_error(CONF_FILTER);
}

static void
lds_error(int error)
{
        switch(error) {
        case CONF_USER:
                ailsa_syslog(LOG_DAEMON, "Cannot get user from config");
                exit(CONF_USER);
                break;
        case CONF_URL:
                ailsa_syslog(LOG_DAEMON, "Cannot get url from config");
                exit(CONF_URL);
                break;
        case CONF_PASS:
                ailsa_syslog(LOG_DAEMON, "Cannot get pass from config");
                exit(CONF_PASS);
                break;
        case CONF_BASE_DN:
                ailsa_syslog(LOG_DAEMON, "Cannot get base DN from config");
                exit(CONF_BASE_DN);
                break;
        case CONF_FILTER:
                ailsa_syslog(LOG_DAEMON, "Cannot get filter from config");
                exit(CONF_FILTER);
                break;
        }
}

static void
parse_lds_command_line(int argc, char *argv[], lds_config_s *config)
{
        const char *optstr = "f:";
        int opt;
#ifdef HAVE_GETOPT_H
	int index;
	struct option lopts[] = {
                {"filter",              required_argument,      NULL,   'f'},
                {NULL,                  0,                      NULL,   0}
        };
        while ((opt = getopt_long(argc, argv, optstr, lopts, &index)) != -1) {
# else
	while ((opt = getopt(argc, argv, optstr)) != -1) {
#endif // HAVE_GETOPT_H
                if (opt == 'f') {
                        config->filter = optarg;
                }
        }
}
