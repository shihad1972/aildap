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
 *  lcou.c
 *
 *  Main file for the lcou program - ldap create organisational unit
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
parse_command_line(int argc, char *argv[], lcou_s *data)
{
	int retval = 0, opt = 0;

	while ((opt = getopt(argc, argv, "d:o:n:fir")) != -1) {
		if (opt == 'd') {
			if ((retval = snprintf(data->domain, DOMAIN, "%s", optarg)) >= DOMAIN)
				rep_truncate("domain", DOMAIN);
		} else if (opt == 'f') {
			data->file = 1;
		} else if (opt == 'i') {
			data->action = 1;
		} else if (opt == 'o') {
			if ((retval = snprintf(data->ou, CANAME, "%s", optarg)) >= CANAME)
				rep_truncate("ou", CANAME);
		} else if (opt == 'n') {
			if ((retval = snprintf(data->newou, CANAME, "%s", optarg)) >= CANAME)
				rep_truncate("newou", CANAME);
		} else if (opt == 'r') {
			data->action = 2;
		} else {
			fprintf(stderr, "Usage: %s ( -i | -r ) -d domain ( -o ou ) -n newou\n",
			 argv[0]);
			return WARG;
		}
	}
	retval = 0;
	if (strlen(data->domain) < 1) {
		fprintf(stderr, "No domain specified\n");
		retval = NODOM;
	}
	if (strlen(data->newou) < 1) {
		fprintf(stderr, "No new ou specified\n");
		retval = NOOU;
	}
	return retval;
}

char *
convert_to_dn(lcou_s *data)
{
	char *ou = 0, *dom, *dn = 0;
	size_t len;

	ou = get_ldif_format(data->ou, "ou", ",");
	if (!(dom = get_ldif_format(data->domain, "dc", ".")))
		return dn;
	if (ou)
		len = strlen(ou) + strlen(dom) + 2;
	else
		len = strlen(dom) + 1;
	if (!(dn = malloc(len)))
		return dn;
	if (ou)
		snprintf(dn, len, "%s,%s", ou, dom);
	else
		snprintf(dn, len, "%s", dom);
	if (ou)
		free(ou);
	free(dom);
	return dn;
}

void
output_ou(char *dn, char *ou, short int ffile)
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
objectClass: top\n\
objectClass: organizationalUnit\n\
ou: %s\n", ou, ou, dn, ou);
	if (ffile > 0)
		fclose(out);
}

int
main(int argc, char *argv[])
{
	char *dn = 0;
	int retval = 0;
	lcou_s *data;

	if (!(data = malloc(sizeof(lcou_s))))
		rep_error("data");
	init_lcou_data_struct(data);
	if ((retval = parse_command_line(argc, argv, data)) == 0) {
		if (!(dn = convert_to_dn(data)))
			goto cleanup;
		output_ou(dn, data->newou, data->file);
	} else {
		rep_usage(argv[0]);
	}
	goto cleanup;
	cleanup:
		clean_lcou_data_struct(data);
		if (dn)
			free(dn);
		return retval;
}

