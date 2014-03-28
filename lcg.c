/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2014  Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  lcg.c
 *
 *  Main file for the lcg program - ldap create group
 *
 *  Part of the ldap collection suite of program
 *
 *  (C) Iain M Conochie 2014 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"

int
parse_lgc_command_line(int argc, char *argv[], lgc_s *data)
{
	int retval = NONE, opt = NONE;

	while ((opt = getopt(argc, argv, "d:g:n:u:")) != -1) {
		if (opt == 'd') {
			if ((retval = snprintf(data->domain, DOMAIN, "%s", optarg)) > DOMAIN) {
				fprintf(stderr, "Domain truncated!\n");
				fprintf(stderr, "Max 255 characters in a domain name\n");
			}
			retval = NONE;
		} else if (opt == 'n') {
			if ((retval = snprintf(data->name, NAME, "%s", optarg)) > NAME) {
				fprintf(stderr, "Name truncated!\n");
				fprintf(stderr, "Max %d characters in a group name\n", NAME);
			}
			retval = NONE;
		} else if (opt == 'g') {
			data->group = (short)strtoul(optarg, NULL, 10);
		} else if (opt == 'u') {
			if ((retval = snprintf(data->users, DN, "%s", optarg)) > DN) {
				fprintf(stderr, "Users truncated!\n");
				fprintf(stderr, "Max %d characters in user list\n", DN);
			}
			retval = NONE;
		} else {
			rep_usage(argv[0]);
			return WARG;
		}
	}
	if (strlen(data->domain) == 0) {
		fprintf(stderr, "No domain specified\n");
		rep_usage(argv[0]);
		retval = NODOM;
	} else if (data->group == 0) {
		fprintf(stderr, "No gid specified\n");
		rep_usage(argv[0]);
		retval = NOGRP;
	} else if (strlen(data->name) == 0) {
		fprintf(stderr, "No group specified\n");
		rep_usage(argv[0]);
		retval = NOGRNM;
	}
	return retval;
}

void
convert_to_dn(lgc_s *data)
{
	char dom[DOMAIN], *tmp = '\0', *dtmp = '\0', *dntmp = '\0';
	int dot = '.', retval = NONE;
	size_t len;

	snprintf(dom, DOMAIN, "%s", data->domain);
	dntmp = data->dn;
	dtmp = dom;
	while ((tmp = strchr(dtmp, dot))) {
		*tmp = '\0';
		if (dtmp == dom) {
			if ((retval = snprintf(data->dc, DC, "%s", dom)) > DC)
				fprintf(stderr, "DC Truncated! Only allowed %d characters\n", DC);
		}
		retval = snprintf(dntmp, DNL, "dc=%s,", dtmp);
		dntmp += retval;
		dtmp = tmp + 1;
	}
	len = strlen(data->dn);
	dntmp = data->dn + len;
	snprintf(dntmp, DNL, "dc=%s", dtmp);
}

void
output_insert_cont(lgc_s *data)
{
	if (!(data))
		return;
	char *grp = data->name, *dn = data->dn, *users = '\0';
	char *tmp, *pos;
	short int gid = data->group;
	if ((strlen(data->users)) > 0)
		users = strndup(data->users, DN);
	printf("\
# %s, group, %s\n\
dn: cn=%s,ou=group,%s\n\
cn: %s\n\
gidNumber: %hd\n\
objectClass: posixGroup\n\
objectClass: top\n", grp, data->domain, grp, dn, grp, gid);
	if (users) {
		tmp = pos = users;
		while ((tmp = strchr(pos, ','))) {
			*tmp = '\0';
			tmp++;
			printf("memberUid: %s\n", pos);
			pos = tmp;
		}
		printf("memberUid: %s\n", pos);
		free(users);
	}
}

int
main(int argc, char *argv[])
{
	int retval = NONE;
	lgc_s *data;

	if (!(data = calloc(ONE, sizeof(lgc_s))))
		rep_error("data");
	init_lgc_data_struct(data);
	if ((retval = parse_lgc_command_line(argc, argv, data)) != 0) {
		clean_lgc_data(data);
		return retval;
	}
	convert_to_dn(data);
	output_insert_cont(data);
	clean_lgc_data(data);
	return retval;
}