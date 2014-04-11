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
 *  ldap-rep.c
 *
 *  Shared function defintions for the ldap-col suite of programs
 *
 *  Part of the ldap collection suite of program
 *
 *  (C) Iain M Conochie 2014 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"
#include "base-sha.h"

int
parse_lcdb_command_line(int argc, char *argv[], lcdb_s *data)
{
	int retval = NONE, opt = NONE;

	if (!(data))
		return ONE;
	while ((opt = getopt(argc, argv, "a:d:p:f")) != -1) {
		if (opt == 'a')
			check_snprintf(data->admin, NAME, optarg, "data->admin");
		else if (opt == 'd')
			check_snprintf(data->domain, DOMAIN, optarg, "data->domain");
		else if (opt == 'p')
			check_snprintf(data->dir, DOMAIN, optarg, "data->dir");
		else if (opt == 'f')
			data->file = 1;
	}
	if ((strlen(data->admin) == 0) || (strlen(data->domain) == 0)) {
		rep_usage(argv[0]);
		return WARG;
	}
	return retval;
}

void
output_db_ldif(lcdb_s *data)
{
	char *ldf, *dir, *dom, *adm, *hsh;
	size_t len;
	FILE *out;

	if (!(data)) {
		fprintf(stderr, "null pointer passed to output_db_ldif\n");
		exit(1);
	}
	dom = data->domain;
	dir = data->dir;
	adm = data->admin;
	hsh = data->phash;
	len = strlen(data->dir);
	ldf = get_ldif_domain(dom);
	if (len == 0)
		snprintf(data->dir, DN, "/var/lib/slapd/%s", dom);
	if (data->file > 0) {
		if (!(out = fopen("db.ldif", "w"))) {
			fprintf(stderr, "Cannot write to db.ldif\n");
			exit(FILE_O_FAIL);
		}
	} else {
		out = stdout;
	}
	fprintf(out, "\
# %s domain, hdb, config\n\
dn: olcDatabase=hdb,cn=config\n\
objectClass: olcDatabaseConfig\n\
objectClass: olcHdbConfig\n\
olcDatabase: hdb\n\
olcDbDirectory: %s\n\
olcSuffix: %s\n\
olcAccess: to attrs=userPassword,shadowLastChange by self write by \
anonymous auth by dn=\"cn=%s,%s\" write by * none\n\
olcAccess: to dn.base="" by * read\n\
olcAccess: to * by self write by dn=\"cn=%s,%s\" write by * read\n\
olcRootDN: cn=%s,%s\n\
olcRootPW: {SSHA}%s\n\
olcDbCheckpoint: 512 30\n\
olcDbConfig: set_cachesize 0 2097152 0\n\
olcDbConfig: set_lk_max_objects 1500\n\
olcDbConfig: set_lk_max_locks 1500\n\
olcDbConfig: set_lk_max_lockers 1500\n\
olcDbIndex: default pres,eq\n\
olcDbIndex: uid\n\
olcDbIndex: cn,sn pres,eq,sub\n\
olcDbIndex: objectClass eq\n\
olcDbIndex: uniqueMember eq\n\
olcDbIndex: uidNumber,gidNumber pres,eq\n",
dom, dir, ldf, adm, ldf, adm, ldf, adm, ldf, hsh);
	if (out != stdout)
		fclose(out);
}

int
main (int argc, char *argv[])
{
	int retval = NONE;
	lcdb_s *data = '\0';

	if (!(data = malloc(sizeof(lcdb_s))))
		rep_error("data");
	init_lcdb_data_struct(data);
	if ((retval = parse_lcdb_command_line(argc, argv, data)) != 0) {
		clean_lcdb_data(data);
		return retval;
	}
	data->pass = getPassword("Enter password for admin DN: ");
	data->phash = get_ldif_pass_hash(data->pass);
	output_db_ldif(data);
	clean_lcdb_data(data);
	return retval;
}
