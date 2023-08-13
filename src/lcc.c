/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2014-2015  Iain M Conochie <iain-AT-thargoid.co.uk>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  lcc.c:
 *
 *  Main file for lcc program: ldap create containers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <ailsaldap.h>

int
parse_command_line(int argc, char *argv[], cont_s *data)
{
	int retval = NONE, opt = NONE;

	while ((opt = getopt(argc, argv, "d:firs")) != -1) {
		if (opt == 'd') {
			if ((retval = snprintf(data->domain, DOMAIN, "%s", optarg)) > DOMAIN) {
				fprintf(stderr, "Domain truncated!\n");
				fprintf(stderr, "Max 255 characters in a domain name\n");
			}
			retval = NONE;
		} else if (opt == 'f') {
			data->file = ONE;
		} else if (opt == 'i') {
			data->action = INSERT;
		} else if (opt == 'r') {
			data->action = REMOVE;
		} else if (opt == 's') {
			data->sudo = ONE;
		} else {
			fprintf(stderr, "Usage: %s [ -i | -r ] -d domain-name (-s)\n", argv[0]);
			return WARG;
		}
	}
	if (strlen(data->domain) == 0) {
		fprintf(stderr, "No domain specified\n");
		fprintf(stderr, "Usage: %s [ -i | -r ] -d domain-name (-s)\n", argv[0]);
		retval = NODOM;
	}
	return retval;
}

void
convert_to_dn(cont_s *data)
{
	char dom[DOMAIN], *tmp = '\0', *dtmp = '\0', *dntmp = '\0';
	int dot = '.', retval = NONE;
	size_t len, dlen;

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
	dlen = strlen(dtmp);
	dntmp = data->dn + len;
	snprintf(dntmp, dlen + 1, "dc=%s", dtmp);
}

void
output_insert_cont(cont_s *data)
{
	FILE *out;
	char *dom = data->domain, *dc = data->dc, *dn = data->dn;
	const char *file = "containers.ldif";
	convert_to_dn(data);
	if (data->file > 0) {
		if (!(out = fopen(file, "w"))) {
			fprintf(stderr, "Cannot open %s for writing!\n", file);
			exit(FILE_O_FAIL);
		}
	} else {
		out = stdout;
	}
	fprintf(out, "\
# %s\n\
dn: %s\n\
dc: %s\n\
objectClass: dcObject\n\
objectClass: top\n\
objectClass: organizationalUnit\n\
ou: %s\n\
\n\
# ou=people %s\n\
dn: ou=people,%s\n\
objectClass: top\n\
objectClass: organizationalUnit\n\
ou: people\n\
\n\
# ou=group %s\n\
dn: ou=group,%s\n\
objectClass: top\n\
objectClass: organizationalUnit\n\
ou: group\n\
\n", dom, dn, dc, dom, dom, dn, dom, dn);
	if (data->sudo > NONE)
		fprintf(out, "\
# ou=SUDOers %s\n\
dn: ou=SUDOers,%s\n\
objectClass: top\n\
objectClass: organizationalUnit\n\
ou: SUDOers\n\
\n", dom, dn);
	if (data->file > 0)
		fclose(out);
}

void
output_remove_cont(cont_s *data)
{
	convert_to_dn(data);
	printf("dn: %s\n", data->dn);
}

int
main(int argc, char *argv[])
{
	int retval = NONE;
	cont_s *data;

	if (!(data = calloc(ONE, sizeof(cont_s))))
		error(MALLOC, errno, "data in main");
	init_lcc_data_struct(data);
	if ((retval = parse_command_line(argc, argv, data)) != 0) {
		clean_lcc_data(data);
		return retval;
	}
	if (data->action == NONE) {
		fprintf(stderr, "No action specified. Assuming insert\n");
		output_insert_cont(data);
	} else if (data->action == INSERT) {
		output_insert_cont(data);
	} else if (data->action == REMOVE) {
		output_remove_cont(data);
	} else {
		fprintf(stderr, "Unknown action %d\n", data->action);
	}
	clean_lcc_data(data);
	return retval;
}
