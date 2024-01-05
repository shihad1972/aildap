/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2014-2015 Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  lcou.c
 *
 *  Main file for the lcou program - ldap create organisational unit
 *
 *  Part of the ldap collection suite of program
 * 
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <libgen.h>
#include <errno.h>
#include <error.h>
#ifdef HAVE_LIBLDAP
# include <ldap.h>
#endif // HAVE_LIBLDAP
#define WANT_OBCL_TOP
#include <ailsa.h>
#include <ailsaldap.h>

int
parse_command_line(int argc, char *argv[], lcou_s *data)
{
	int retval = 0, opt = 0;

	while ((opt = getopt(argc, argv, "ad:o:n:fir")) != -1) {
		if (opt == 'a') {
			data->ldap = true;
		} else if (opt == 'd') {
			data->dn = optarg;
		} else if (opt == 'f') {
			data->file = 1;
		} else if (opt == 'i') {
			data->action = ACT_ADD;
		} else if (opt == 'o') {
			data->ou = optarg;
		} else if (opt == 'n') {
			data->newou = optarg;
		} else if (opt == 'r') {
			data->action = ACT_DEL;
		} else {
			fprintf(stderr, "Usage: %s [ -a ] [ -i | -r ] -d dn [ -o ou ] -n newou\n",
			 argv[0]);
			return WARG;
		}
	}
	retval = 0;
#ifndef HAVE_LIBLDAP
	if (data->ldap) {
		fprintf(stderr, "You have requested adding to an ldap directory, \
but this program is not linked against an ldap library\n");
		retval = NOLDAP;
	}
#endif // HAVE_LIBLDAP
	if (data->action == 0)
		data->action = ACT_ADD;	// default is to add to ldap
	if (!(data->dn)) {
		fprintf(stderr, "No dn specified\n");
		retval = NODOM;
	}
	if (!(data->newou)) {
		fprintf(stderr, "No new ou specified\n");
		retval = NOOU;
	}
	return retval;
}

void
fill_lcou_config(lcou_s *ou, AILSA_LIST *list)
{
	ou->dn = get_value_from_kv_list(list, "base");
	ou->url = get_value_from_kv_list(list, "url");
	ou->user = get_value_from_kv_list(list, "user");
	ou->pass = get_value_from_kv_list(list, "pass");
}

char *
convert_to_dn(lcou_s *data)
{
	char *ou = 0, *dn = 0;
	size_t len;

	ou = get_ldif_format(data->ou, "ou", ",");
	if (ou)
		len = strlen(ou) + strlen(data->dn) + 2;
	else
		len = strlen(data->dn) + 1;
	if (!(dn = malloc(len)))
		return dn;
	if (ou)
		snprintf(dn, len, "%s,%s", ou, data->dn);
	else
		snprintf(dn, len, "%s", data->dn);
	if (ou)
		free(ou);
	return dn;
}

void
output_ou(const char *dn, const char *ou, short int ffile)
{
	FILE *out;
	const char *file = "ou.ldif";
	if (ffile > 0) {
		if (!(out = fopen(file, "w"))) {
			fprintf(stderr, "Cannot open %s for writing\n", file);
			exit(FILE_O_FAIL);
		}
	} else {
		out = stdout;
	}
	fprintf(out, "\
# ou=%s\n\
dn: ou=%s,%s\n\
%s\n\
objectClass: organizationalUnit\n\
ou: %s\n", ou, ou, dn, obcl_top, ou);
	if (ffile > 0)
		fclose(out);
}

int
add_ou_to_ldap(lcou_s *ou, const char *dn)
{
	int retval = 0;
	char *newdn = ailsa_calloc(RBUFF_S, "newdn in add_ou_to_ldap");
	LDAP *ld;
	LDAPMod **mod = ailsa_calloc(sizeof(mod) * AILSA_OU_CLASS, "mod in add_ou_to_ldap");
	char **values;

	if (!(ou)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}
	if (ou->url) {
		ailsa_ldap_init(&ld, ou->url);
	} else {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}
	if ((retval = snprintf(newdn, RBUFF_S, "ou=%s,%s", ou->newou, dn)) >= RBUFF_S)
		ailsa_syslog(LOG_DAEMON, "newdn truncated in add_ou_to_ldap");
	mod[0] = ailsa_calloc(sizeof(mod), "mod[0] in add_ou_to_ldap");
	values = ailsa_calloc(sizeof(values) * 2, "values #1 in add_ou_to_ldap");
	values[0] = strndup(ou->newou, RBUFF_S);
	if ((retval = ailsa_ldap_mod_str_pack(mod[0], 0, strdup("ou"), values)) != 0)
		goto cleanup;
	mod[1] = ailsa_calloc(sizeof(mod), "mod[1] in add_ou_to_ldap");
	values = ailsa_calloc(sizeof(values) * 3, "values #2 in add_ou_to_ldap");
	values[0] = strdup("top");
	values[1] = strdup("organizationalUnit");
	if ((retval = ailsa_ldap_mod_str_pack(mod[1], 0, strdup("objectClass"), values)) != 0)
		goto cleanup;
	if ((retval = ldap_simple_bind_s(ld, ou->user, ou->pass)) != 0) {
		ailsa_syslog(LOG_DAEMON, "bind failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	if ((retval = ldap_add_ext_s(ld, newdn, mod, NULL, NULL)) != 0) {
		ailsa_syslog(LOG_DAEMON, "Adding failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	cleanup:
		my_free(newdn);
		ldap_mods_free(mod, true);
		if (ld)
			ldap_unbind(ld);
		return retval;
}

int
del_ou_from_ldap(lcou_s *ou, const char *dn)
{
	int retval = 0;
	char *newdn = ailsa_calloc(RBUFF_S, "newdn in del_ou_from_ldap");
	LDAP *ld;

	if (!(ou)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}
	if (ou->url) {
		ailsa_ldap_init(&ld, ou->url);
	} else {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}
	if ((retval = snprintf(newdn, RBUFF_S, "ou=%s,%s", ou->newou, dn)) >= RBUFF_S)
		ailsa_syslog(LOG_DAEMON, "newdn truncated in add_ou_to_ldap");
	if ((retval = ldap_simple_bind_s(ld, ou->user, ou->pass)) != 0) {
		ailsa_syslog(LOG_DAEMON, "bind failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	if ((retval = ldap_delete_s(ld, newdn)) != 0) {
		ailsa_syslog(LOG_DAEMON, "delete failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	cleanup:
		my_free(newdn);
		return retval;
}

int
main(int argc, char *argv[])
{
	char *dn = 0;
	int retval = 0;
	lcou_s *data;
	AILSA_LIST *list;

	if (!(data = ailsa_calloc(sizeof(lcou_s), "data in main")))
		error(MALLOC, errno, "data in main");
	create_kv_list(&list);
	aildap_parse_config(list, basename(argv[0]));
	fill_lcou_config(data, list);
	if ((retval = parse_command_line(argc, argv, data)) == 0) {
		if (!(dn = convert_to_dn(data)))
			goto cleanup;
		if (data->ldap && (data->action == ACT_ADD))
			retval = add_ou_to_ldap(data, dn);
		else if (data->ldap && (data->action == ACT_DEL))
			retval = del_ou_from_ldap(data, dn);
		else
			output_ou(dn, data->newou, data->file);
	} else {
		rep_usage(argv[0]);
	}
	goto cleanup;
	cleanup:
		my_free(data);
		destroy_kv_list(list);
		if (dn)
			free(dn);
		return retval;
}

