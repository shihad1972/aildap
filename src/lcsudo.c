/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2015  Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  lcsudo.c
 *
 *  Main file for the lcsudo program - ldap create sudoers
 *
 *  Part of the ldap collection suite of program
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <ailsaldap.h>

int
parse_command_line(int argc, char *argv[], lcsudo_s *data)
{
	int opt;

	while ((opt = getopt(argc, argv, "d:e:h:g:o:p:u:fimr")) != -1) {
		if (opt == 'd')
			check_snprintf(data->domain, DOMAIN, optarg, "data->domain");
		else if (opt == 'e')
			check_snprintf(data->ruser, NAME, optarg, "data->ruser");
		else if (opt == 'h')
			check_snprintf(data->host, CANAME, optarg, "data->host");
		else if (opt == 'g')
			check_snprintf(data->group, GROUP, optarg, "data->group");
		else if (opt == 'o')
			check_snprintf(data->com, DOMAIN, optarg, "data->com");
		else if (opt == 'p')
			check_snprintf(data->rgroup, GROUP, optarg, "data->rgroup");
		else if (opt == 'u')
			check_snprintf(data->user, NAME, optarg, "data->user");
		else if (opt == 'f')
			data->file = 1;
		else if (opt == 'i')
			data->action = INSERT;
		else if (opt == 'm')
			data->action = MODIFY;
		else if (opt == 'r')
			data->action = REMOVE;
		else
			goto cleanup;
	}
	if (argc == 1)
		goto cleanup;
	if (data->action == 0)
		goto cleanup;
	if (data->action == INSERT && (strlen(data->domain) == 0 ||
	   (strlen(data->user) == 0 && strlen(data->group) == 0) ||
	    strlen(data->com) == 0 || strlen(data->host) == 0))
		goto cleanup;
	if (data->action == MODIFY && (strlen(data->domain) == 0 ||
	   (strlen(data->user) == 0 && strlen(data->group) == 0) ||
	   (strlen(data->com) == 0 && strlen(data->host) == 0 &&
	    strlen(data->ruser) == 0 && strlen(data->rgroup) == 0)))
		goto cleanup;
	if (data->action == REMOVE && (strlen(data->domain) == 0 ||
	   (strlen(data->user) == 0 && strlen(data->group) == 0)))
		goto cleanup;
	if (strlen(data->user) > 0 && strlen(data->group) > 0) {
		fprintf(stderr, "Both user and group supplied\n");
		goto cleanup;
	}
	return 0;

	cleanup:
		rep_usage(argv[0]);
		return WARG;
}

char *
get_sudo_dn(lcsudo_s *sudo)
{
	char *cn, *domain;
	int test = 0;

	if (!(domain = get_ldif_format(sudo->domain, "dc", ".")))
		return NULL;
	if (!(cn = malloc(BBUFF)))
		return NULL;
	if (strlen(sudo->user) > 0)
		snprintf(cn, BBUFF, "cn=%s,ou=SUDOers,%s", sudo->user, domain);
	else if (strlen(sudo->group) > 0)
		snprintf(cn, BBUFF, "cn=%%%s,ou=SUDOers,%s", sudo->group, domain);
	else
		test = 1;
	free(domain);
	if (test > 0) {
		free(cn);
		return NULL;
	} else {
		return cn;
	}
}

void
output_insert_sudoers_ldif(lcsudo_s *sudo, char *dn, FILE *out)
{
	fprintf(out, "\
# %s\n\
dn: %s\n\
objectClass: top\n\
objectClass: sudoRole\n\
", dn, dn);
	if (strlen(sudo->user) > 0)
		fprintf(out, "\
cn: %s\n\
sudoUser: %s\n\
", sudo->user, sudo->user);
	else if (strlen(sudo->group) > 0)
		fprintf(out, "\
cn: %%%s\n\
sudoUser: %%%s\n\
", sudo->group, sudo->group);
	else	// Fall through, although should be impossible
		return;
	fprintf(out, "\
sudoCommand: %s\n\
sudoHost: %s\n\
", sudo->com, sudo->host);
	if (strlen(sudo->ruser) > 0)
		fprintf(out, "\
sudoRunAsUser: %s\n", sudo->ruser);
	else
		fprintf(out, "\
sudoRunAsUser: ALL\n");
	if (strlen(sudo->rgroup) > 0)
		fprintf(out, "\
sudoRunAsGroup: %%%s\n", sudo->rgroup);
	else
		fprintf(out, "\
sudoRunAsGroup: ALL\n");
}

void
output_remove_sudoers_ldif(lcsudo_s *sudo, char *dn, FILE *out)
{
	int i = 0;

	if (strlen(sudo->com) == 0 && strlen(sudo->host) == 0) {
		fprintf(out, "\
# %s\n\
dn: %s\n\
changeType: delete\n\
", dn, dn);
	} else {
		fprintf(out, "\
# %s\n\
dn: %s\n\
changeType: modify\n\
", dn, dn);
		if (strlen(sudo->com) > 0) {
			fprintf(out, "\
delete: sudoCommand\n\
sudoCommand: %s\n\
", sudo->com);
			i++;
		}
		if (strlen(sudo->host) > 0) {
			if (i > 0)
				fprintf(out, "--\n");
			fprintf(out, "\
delete: sudoHost\n\
sudoHost: %s\n\
", sudo->host);
		}
	}
}

void
output_modify_sudoers_ldif(lcsudo_s *sudo, char *dn, FILE *out)
{
	int i = 0;
	fprintf(out, "\
# %s\n\
dn: %s\n\
changeType: modify\n\
", dn, dn);
	if (strlen(sudo->com) > 0) {
		fprintf(out, "\
add: sudoCommand\n\
sudoCommand: %s\n\
", sudo->com);
		i++;
	}
	if (strlen(sudo->host) > 0) {
		if (i > 0)
			fprintf(out, "--\n");
		fprintf(out, "\
add: sudoHost\n\
sudoHost: %s\n\
", sudo->host);
		i++;
	}
	if (strlen(sudo->ruser) > 0) {
		if (i > 0)
			fprintf(out, "--\n");
		fprintf(out, "\
add: sudoRunAsUser\n\
sudoRunAsUser: %s\n\
", sudo->ruser);
		i++;
	}
	if (strlen(sudo->rgroup) > 0) {
		if (i > 0)
			fprintf(out, "--\n");
		fprintf(out, "\
add: sudoRunAsGroup\n\
sudoRunAsGroup: %s\n\
", sudo->rgroup);
	}
}

void
output_sudo_ldif(lcsudo_s *sudo)
{
	char *dn = 0;
	FILE *out;
	const char *file = "sudo.ldif";

	if (sudo->file > 0) {
		if (!(out = fopen(file, "w"))) {
			fprintf(stderr, "Cannot open %s for writing\n", file);
			goto cleanup;
		}
	} else {
		out = stdout;
	}
	if (!(dn = get_sudo_dn(sudo))) {
		if (sudo->file > 0)
			fclose(out);
		goto cleanup;
	}
	if (sudo->action == INSERT)
		output_insert_sudoers_ldif(sudo, dn, out);
	else if (sudo->action == MODIFY)
		output_modify_sudoers_ldif(sudo, dn, out);
	else if (sudo->action == REMOVE)
		output_remove_sudoers_ldif(sudo, dn, out);
	else  // Fall through
		goto cleanup;
	if (sudo->file > 0)
		fclose(out);
	free(dn);
	return;

	cleanup:
		fprintf(stderr, "Action is not insert, modify, or remove");
		if (dn)
			free(dn);
		clean_lcsudo_data(sudo);
		exit(1);
}

int
main(int argc, char *argv[])
{
	int retval = 0;
	lcsudo_s *sudo = 0;

	if (!(sudo = malloc(sizeof(lcsudo_s))))
		error(MALLOC, errno, "sudo in main");
	init_lcsudo_data_struct(sudo);
	if ((retval = parse_command_line(argc, argv, sudo)) != 0)
		return retval;
	output_sudo_ldif(sudo);
	clean_lcsudo_data(sudo);
	return 0;
}

