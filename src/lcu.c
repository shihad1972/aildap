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
 *  lcu.c:
 * 
 *  Main function for the program to create user entries in the ldap
 *  directory
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"
#include "base-sha.h"
#include "../config.h"

int
parse_command_line(int argc, char *argv[], inp_data_s *data)
{
	int opt = NONE, slen = NONE;

	while ((opt = getopt(argc, argv, "d:gln:pu:")) != -1) {
		if (opt == 'd') {
			GET_OPT_ARG(dom, DOMAIN, Domain)
		} else if (opt == 'g') {
			data->gr = ONE;
		} else if (opt == 'l') {
			data->lu = ONE;
#ifdef HAVE_OPENSSL
		} else if (opt == 'p') {
			data->np = ONE;
#endif /* HAVE_OPENSSL */
		} else if (opt == 'n') {
			GET_OPT_ARG(name, USER, Name)
		} else if (opt == 'u') {
			if (optarg)
				data->user = (short)strtoul(optarg, NULL, DECIMAL);
			else
				fprintf(stderr, "No userid specified\n");
		} else {
			rep_usage(argv[0]);
			return ONE;
		}
	}
	if (strlen(data->dom) == 0) {
		fprintf(stderr, "No domain specified\n");
		rep_usage(argv[0]);
		exit (1);
	} else if (strlen(data->name) == 0) {
		fprintf(stderr, "No name specified\n");
		rep_usage(argv[0]);
		exit (1);
	} else if (data->user == 0) {
		fprintf(stderr, "No userid specified\n");
		rep_usage(argv[0]);
		exit (1);
	}
	return NONE;
}

int
main (int argc, char *argv[])
{
#ifdef HAVE_OPENSSL
	char *pass;
#endif /* HAVE_OPENSSL */
	int retval = 0;
	inp_data_s *data;

	if (!(data = malloc(sizeof(inp_data_s))))
		rep_err("data in main");
	init_lcu_data(data);
	parse_command_line(argc, argv, data);
	split_name(data);
#ifdef HAVE_OPENSSL
	if (data->np == 0) {
		pass = getPassword("Enter password for user: ");
		snprintf(data->pass, DOMAIN, "%s", pass);
		free(pass);
	}
#endif /* HAVE_OPENSSL */
	output_ldif(data);
	clean_lcu_data(data);
	return retval;
}
