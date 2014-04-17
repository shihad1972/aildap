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
 *  lck.c
 *
 *  Main file for the lcg program - ldap create group
 *
 *  Part of the ldap collection suite of program
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"

int
parse_lck_command_line(int argc, char *argv[], lck_s *data)
{
	int retval = 0, opt = 0;

	while ((opt = getopt(argc, argv, "fh:r:")) != -1) {
		if (opt == 'f')
			data->file = 1;
		if (opt == 'h')
			check_snprintf(data->host, DOMAIN, optarg, "data->host");
		else if (opt == 'r')
			check_snprintf(data->realm, DOMAIN, optarg, "data->realm");
		else {
			rep_usage(argv[0]);
			return WARG;
		}
	}
	if ((strlen(data->host) == 0) || (strlen(data->realm) == 0)) {
		rep_usage(argv[0]);
		return WARG;
	}
	return retval;
}

int
print_lck_ldif(lck_s *data)
{
	const char *file = "sasl.ldif";
	FILE *out;
	if (!(data))
		return NODATA;
	if (data->file > 0) {
		if (!(out = fopen(file, "w")))
			return FILE_O_FAIL;
	} else {
		out = stdout;
	}
	fprintf(out, "\
dc: cn=config\n\
changeType: modify\n\
add: olcSaslHost\n\
olcSaslHost: %s\n\
-\n\
add: olcSaslRealm\n\
olcSaslRealm: %s\n", data->host, data->realm);
	if (data->file > 0)
		fclose(out);
	return 0;
}

int
main (int argc, char *argv[])
{
	int retval = NONE;
	lck_s *data;

	if (!(data = malloc(sizeof(lck_s))))
		rep_error("data");
	init_lck_data_struct(data);
	if ((retval = parse_lck_command_line(argc, argv, data)) > 0) {
		clean_lck_data_struct(data);
		return retval;
	}
	print_lck_ldif(data);
	clean_lck_data_struct(data);
	return retval;
}