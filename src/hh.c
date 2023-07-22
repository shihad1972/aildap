/* 
 *
 *  hh: hostname hash
 *  Copyright (C) 2018  Iain M Conochie <iain-AT-thargoid.co.uk> 
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
 *  hh.c
 *
 *  output hash of the current hostname. Optionally take command line arg
 *    of hostname to hash
 */

#include <config.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif // HAVE_GETOPT_H
#include <ailsaldap.h>

static int
parse_hh_command_line(int argc, char *argv[], char **name);

static int
output_hash_hostname(char *name);

int
main(int argc, char *argv[])
{
	int retval = 0;
	char *name = NULL;

	if ((retval = parse_hh_command_line(argc, argv, &name)) != 0) {
		switch(retval) {
		case ACT_HELP:
			rep_usage("hh");
			break;
		}
	}
	if (retval == 0)
		retval = output_hash_hostname(name);
	if (name)
		free(name);
	return retval;
}

static int
parse_hh_command_line(int argc, char *argv[], char **name)
{
	int retval, opt, trim;
	retval = 0;
	const char *optstr = "n:hv";
#ifdef HAVE_GETOPT_H
	int index;
	struct option lopts[] = {
		{"hostname",		required_argument,	NULL,	'n'},
		{"name",		required_argument,	NULL,	'n'},
		{NULL,			0,			NULL,	0}
	};
	while ((opt = getopt_long(argc, argv, optstr, lopts, &index)) != -1)
#else
	while ((opt = getopt(argc, argv, optstr)) != -1)
#endif // HAVE_GETOPT_H
	{
		if (opt == 'n') {
			if (!(*name = malloc(DOMAIN)))
				rep_err("name in parse_hh_command_line");
			if ((trim = snprintf(*name, DOMAIN, "%s", optarg)) >= DOMAIN)
				fprintf(stderr, "Hostname %s trimmed! 255 characters max!\n", *name);
		} else if (opt == 'v') {
			output_version("hh");
		} else if (opt == 'h') {
			retval = ACT_HELP;
		} else {
			fprintf(stderr, "Unknown option: %c\n", opt);
			retval = ACT_HELP;
		}
	}
	return retval;
}

static int
output_hash_hostname(char *name)
{
	int retval = 0;
	unsigned char *hash;

	if (!name) {
		if (!(name = malloc(DOMAIN)))
			rep_err("name in output_hash_hostname");
		if ((retval = gethostname(name, DOMAIN)) != 0) {
			fprintf(stderr, "gethostname: %s\n", strerror(errno));
			free(name);
			return retval;
		}
	}
	if (!(hash = ailsa_hash_string(name, "sha1")))
		return 1;
	retval = output_hex_conversion(hash, "sha1");
	free(hash);
	return retval;
}

