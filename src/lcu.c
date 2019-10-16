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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif // HAVE_GETOPT_H
#include <errno.h>
#include <error.h>
#include <ailsaldap.h>

int
parse_command_line(int argc, char *argv[], inp_data_s *data)
{
	const char *optstr = "d:ghln:pu:vG:U:";
	int opt, slen, retval;
	opt = slen = retval = 0;

#ifdef HAVE_GETOPT_H
	int index;
	struct option lopts[] = {
		{"domain",		required_argument,	NULL,	'd'},
		{"group",		no_argument,		NULL,	'g'},
		{"help",		no_argument,		NULL,	'h'},
		{"long-name",		no_argument,		NULL,	'l'},
		{"name",		required_argument,	NULL,	'n'},
		{"no-password",		no_argument,		NULL,	'p'},
		{"userid",		required_argument,	NULL,	'u'},
		{"version", 		no_argument,		NULL,	'v'},
		{"group-ou",		required_argument,	NULL,	'G'},
		{"user-ou",		required_argument,	NULL,	'U'},
		{NULL,			0,			NULL,	0}
	};
	while ((opt = getopt_long(argc, argv, optstr, lopts, &index)) != -1) {
# else
	while ((opt = getopt(argc, argv, optstr)) != -1) {
#endif // HAVE_GETOPT_H
		if (opt == 'd') {
			if (!(data->dom = strndup(optarg, DOMAIN)))
				error(MALLOC, errno, "data->dom");
		} else if (opt == 'g') {
			data->gr = ONE;
		} else if (opt == 'l') {
			data->lu = ONE;
		} else if (opt == 'p') {
			data->np = ONE;
		} else if (opt == 'n') {
			if (!(data->name = strndup(optarg, NAME)))
				error(MALLOC, errno, "data->name");
		} else if (opt == 'u') {
			if (optarg)
				data->user = (short)strtoul(optarg, NULL, DECIMAL);
			else
				fprintf(stderr, "No userid specified\n");
		} else if (opt == 'h') {
			rep_usage(argv[0]);
			exit (0);
		} else if (opt == 'v') {
			fprintf(stderr, "%s: %s\n", argv[0], VERSION);
			exit (0);
		} else if (opt == 'G') {
			if (!(data->gou = strndup(optarg, DOMAIN)))
				error(MALLOC, errno, "data->gou");
		} else if (opt == 'U') {
			if (!(data->uou = strndup(optarg, DOMAIN)))
				error(MALLOC, errno, "data->uou");
		} else {
			rep_usage(argv[0]);
			return ONE;
		}
	}
	if (!(data->dom)) {
		fprintf(stderr, "No domain specified\n");
		rep_usage(argv[0]);
		exit (1);
	} else if (!(data->name)) {
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
	char *pass;
	int retval = 0;
	inp_data_s *data;

	if (!(data = malloc(sizeof(inp_data_s))))
		rep_err("data in main");
	memset (data, 0, sizeof(inp_data_s));
	parse_command_line(argc, argv, data);
	split_name(data);
	if (data->np == 0) {
		pass = getPassword("Enter password for user: ");
		data->pass = strndup(pass, DOMAIN);
		free(pass);
	}
	output_ldif(data);
	clean_lcu_data(data);
	return retval;
}
