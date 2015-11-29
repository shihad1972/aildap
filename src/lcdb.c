/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2014-2015  Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  lcdb.c
 *
 *  Create the ldif for a new database on the ldap server.
 *
 *  Part of the ldap collection suite of program
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <ailsaldap.h>

int
parse_lcdb_command_line(int argc, char *argv[], lcdb_s *data)
{
	int retval = NONE, opt = NONE;

	if (!(data))
		return ONE;
	while ((opt = getopt(argc, argv, "a:d:p:ft:")) != -1) {
		if (opt == 'a') {
			check_snprintf(data->admin, NAME, optarg, "data->admin");
		} else if (opt == 'd') {
			check_snprintf(data->domain, DOMAIN, optarg, "data->domain");
		} else if (opt == 'p') {
			check_snprintf(data->dir, DOMAIN, optarg, "data->dir");
		} else if (opt == 'f') {
			data->file = 1;
		} else if (opt == 't') {
			if (strncmp(optarg, "hdb", DB) == 0)
				data->type = HDB;
			else if (strncmp(optarg, "mdb", DB) == 0)
				data->type = MDB;
		}
	}
	if ((strlen(data->admin) == 0) || (strlen(data->domain) == 0)) {
		rep_usage(argv[0]);
		return WARG;
	}
	if (data->type == 0) {
		fprintf(stderr, "Invalid or missing database type\n");
		retval = NOTYPE;
	}
	return retval;
}

void
output_db_ldif(lcdb_s *data)
{
	char *ldf, *dir, *dom, *adm;
#ifdef HAVE_OPENSSL
	char *hsh;
#else
	char *pass;
#endif /* HAVE_OPENSSL */
	size_t len;
	FILE *out;

	if (!(data)) {
		fprintf(stderr, "null pointer passed to output_db_ldif\n");
		exit(1);
	}
	dom = data->domain;
	dir = data->dir;
	adm = data->admin;
#ifdef HAVE_OPENSSL
	hsh = data->phash;
#else
	pass = data->pass;
#endif /* HAVE_OPENSSL */
	len = strlen(data->dir);
	ldf = get_ldif_domain(dom);
	if (len == 0)
		snprintf(data->dir, DN, "/var/lib/slapd/%s/domain", dom);
	if (data->file > 0) {
		if (!(out = fopen("db.ldif", "w"))) {
			fprintf(stderr, "Cannot write to db.ldif\n");
			exit(FILE_O_FAIL);
		}
	} else {
		out = stdout;
	}
	if (data->type == HDB) {
		fprintf(out, "\
# %s domain, hdb, config\n\
dn: olcDatabase=hdb,cn=config\n\
objectClass: olcDatabaseConfig\n\
objectClass: olcHdbConfig\n\
olcDatabase: hdb\n", dom);
	} else if (data->type == MDB) {
		fprintf(out, "\
# %s domain, mdb, config\n\
dn: olcDatabase=mdb,cn=config\n\
objectClass: olcDatabaseConfig\n\
objectClass: olcMdbConfig\n\
olcDatabase: mdb\n", dom);
	}
	fprintf(out, "\
olcDbDirectory: %s\n\
olcSuffix: %s\n\
olcAccess: to attrs=userPassword,shadowLastChange by self write by \
anonymous auth by dn=\"cn=%s,%s\" write by * none\n\
olcAccess: to dn.base="" by * read\n\
olcAccess: to * by self write by dn=\"cn=%s,%s\" write by * read\n\
olcRootDN: cn=%s,%s\n", dir, ldf, adm, ldf, adm, ldf, adm, ldf);
#ifdef HAVE_OPENSSL
	fprintf(out, "olcRootPW: {SSHA}%s\n", hsh);
#else
	fprintf(out, "olcRootPW: %s\n", pass);
#endif /* HAVE_OPENSSL */
	fprintf(out, "\
olcDbCheckpoint: 512 30\n");
	if (data->type == HDB) {
		fprintf(out, "\
olcDbConfig: set_cachesize 0 2097152 0\n\
olcDbConfig: set_lk_max_objects 1500\n\
olcDbConfig: set_lk_max_locks 1500\n\
olcDbConfig: set_lk_max_lockers 1500\n\
olcDbIndex: default sub\n\
olcDbIndex: uidNumber,gidNumber pres,eq\n\
olcDbIndex: uid,cn,sn pres,eq,sub\n\
olcDbIndex: memberUid,uniqueMember,objectClass eq\n");
	} else if (data->type == MDB) {
		fprintf(out, "\
olcDbIndex: default sub\n\
olcDbIndex: uidNumber,gidNumber pres,eq\n\
olcDbIndex: uid,cn,sn pres,eq,sub\n\
olcDbIndex: memberUid,uniqueMember,objectClass eq\n\
olcDbMaxSize: 1073741824\n");
	} else {
		fprintf(stderr, "No database type??");
	}
	if (out != stdout)
		fclose(out);
}

int
main (int argc, char *argv[])
{
	int retval = NONE;
	lcdb_s *data = '\0';

	if (!(data = malloc(sizeof(lcdb_s))))
		error(MALLOC, errno, "data in main");
	init_lcdb_data_struct(data);
	if ((retval = parse_lcdb_command_line(argc, argv, data)) != 0) {
		clean_lcdb_data(data);
		return retval;
	}
	data->pass = getPassword("Enter password for admin DN: ");
	if (strlen(data->pass) > 0) {
#ifdef HAVE_OPENSSL
		data->phash = get_ldif_pass_hash(data->pass);
#endif /* HAVE_OPENSSL */
		output_db_ldif(data);
	} else {
		fprintf(stderr, "Empty password!\n");
	}
	clean_lcdb_data(data);
	return retval;
}
