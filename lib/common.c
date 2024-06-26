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
 *  common.c
 *
 *  Shared function defintions for the ailsa ldap library
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
#include <ctype.h>
#include <ailsaldap.h>

void
rep_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s ", prog);
	if (strstr(prog, "lcr")) 
		fprintf(stderr, "-d domain -h host -u user\
 -b db# -p db# -r db# [ -f ] [ -s | -t ] [ -C | -P ] [ -M ] [ -c ca-cert]\n");
	else if (strstr(prog, "lcg"))
		fprintf(stderr, "-d domain-name -g gid -n group\
 [ -u user1,user2,...,userN ]\n");
	else if (strstr(prog, "lck"))
		fprintf(stderr, "-h hostname -r realm\n");
	else if (strstr(prog, "lcdb"))
		fprintf(stderr, "-a admin-user -d domain -t db-type [ -p path ] [ -f ]\n");
	else if (strstr(prog, "lcsudo"))
		fprintf(stderr, "\
-d domain ( -g group | -u user ) -o command -h host\n\
( -i | -m | -r ) [ -e RunAsUser | -p RunAsGroup ] [ -f ]\n");
	else if (strstr(prog, "lcs"))
		fprintf(stderr, "-h hostname [ -a CA-cert ] [ -i | r ]\n");
	else if (strstr(prog, "lcou"))
		fprintf(stderr, "-d domain -n newou ( -o comma seperated list of ou's) ( -i | -r )\n");
	else if (strstr(prog, "lcu")) {
		fprintf(stderr, "\
-d domain [ -g ] [ -l ] [ -p ] [ -s ] -n full-name -u userid [ -G group-ou ] [ -U users-ou ]\n\
-g: create group for the user (same name and id)\n\
-l: create long user name (first initial plus surname)\n\
-p: do not ask for a password\n\
-s: create a Simple Security Object user\n");
	} else if (strstr(prog, "hh")) {
		fprintf(stderr, "[ -n hostname ]\n");
	}
}

void
rep_truncate(const char *what, int max)
{
	fprintf(stderr, "%s truncated. Max allowed is %d\n", what, max - 1);
}

void
rep_err(const char *error)
{
	fprintf(stderr, "%s\n", error);
	exit (MEM);
}

int
init_lcu_data(inp_data_s *data) 
{
	if (!data)
		return ONE;
	memset(data, 0, sizeof(inp_data_s));
	MALLOC_DATA_MEMBER(dom, DOMAIN);
	MALLOC_DATA_MEMBER(pass, DOMAIN);
	MALLOC_DATA_MEMBER(sur, SURNAME);
	MALLOC_DATA_MEMBER(uname, SURNAME);
	MALLOC_DATA_MEMBER(fname, SURNAME);
	MALLOC_DATA_MEMBER(name, USER);
	return NONE;
}

void
clean_lcu_data(inp_data_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(dom)
		CLEAN_DATA_MEMBER(pass)
		CLEAN_DATA_MEMBER(sur)
		CLEAN_DATA_MEMBER(name)
		CLEAN_DATA_MEMBER(uname)
		CLEAN_DATA_MEMBER(fname)
		CLEAN_DATA_MEMBER(gou);
		CLEAN_DATA_MEMBER(uou);
		free(data);
	}
}

void
init_lcr_data_struct(lcr_t *data)
{
	if (data) {
		memset(data, 0, sizeof(lcr_t));
		MALLOC_DATA_MEMBER(host, DOMAIN);
		MALLOC_DATA_MEMBER(domain, DOMAIN);
		MALLOC_DATA_MEMBER(user, NAME);
		MALLOC_DATA_MEMBER(db, DB);
		MALLOC_DATA_MEMBER(ca, DOMAIN);
		MALLOC_DATA_MEMBER(cdb, DB);
		MALLOC_DATA_MEMBER(pdb, DB);
	} else {
		fprintf(stderr, "null pointer passed to init_lcr_data_struct\n");
		exit(1);
	}
}

void
clean_lcr_data_struct(lcr_t *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(host);
		CLEAN_DATA_MEMBER(domain);
		CLEAN_DATA_MEMBER(user);
		CLEAN_DATA_MEMBER(db);
		CLEAN_DATA_MEMBER(ca);
		CLEAN_DATA_MEMBER(cdb);
		CLEAN_DATA_MEMBER(pdb);
		free(data);
	}
}

void
init_lgc_data_struct(lgc_s *data)
{
	if (data) {
		memset(data, 0, sizeof(lgc_s));
		MALLOC_DATA_MEMBER(domain, DOMAIN);
		MALLOC_DATA_MEMBER(dc, DC);
		MALLOC_DATA_MEMBER(dn, DN);
		MALLOC_DATA_MEMBER(name, NAME);
		MALLOC_DATA_MEMBER(user, DN);
	} else {
		fprintf(stderr, "null pointer passed to init_lgc_data_struct\n");
		exit(1);
	}
}


void
init_lck_data_struct(lck_s *data)
{
	if (data) {
		memset(data, 0, sizeof(lck_s));
		MALLOC_DATA_MEMBER(host, DOMAIN);
		MALLOC_DATA_MEMBER(realm, DOMAIN);
	} else {
		fprintf(stderr, "null pointer passed to init_lck_data_struct\n");
		exit(1);
	}
}

void
clean_lck_data_struct(lck_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(host);
		CLEAN_DATA_MEMBER(realm);
		free(data);
	}
}

void
clean_lgc_data(lgc_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(domain);
		CLEAN_DATA_MEMBER(dc);
		CLEAN_DATA_MEMBER(dn);
		CLEAN_DATA_MEMBER(name);
		CLEAN_DATA_MEMBER(user);
		free(data);
	}
}

void
init_lcdb_data_struct(lcdb_s *data)
{
	if (data) {
		memset(data, 0, sizeof(lcdb_s));
		MALLOC_DATA_MEMBER(domain, DOMAIN);
		MALLOC_DATA_MEMBER(admin, NAME);
		MALLOC_DATA_MEMBER(dir, DN);
	} else {
		fprintf(stderr, "null pointer passed to init_lcdb_data_struct\n");
		exit(1);
	}
}

void
clean_lcdb_data(lcdb_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(domain);
		CLEAN_DATA_MEMBER(admin);
		CLEAN_DATA_MEMBER(phash);
		CLEAN_DATA_MEMBER(pass);
		CLEAN_DATA_MEMBER(dir);
		free(data);
	}
}

void
init_lcs_data_struct(cert_s *data)
{
	if (data) {
		memset(data, 0, sizeof(cert_s));
		MALLOC_DATA_MEMBER(hostname, DOMAIN);
		MALLOC_DATA_MEMBER(ca, CANAME);
	} else {
		fprintf(stderr, "null pointer passed to init_lcs_data_struct");
		exit(1);
	}
}

void
clean_lcs_data(cert_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(hostname);
		CLEAN_DATA_MEMBER(ca);
		free(data);
	}
}

void
init_lcsudo_data_struct(lcsudo_s *data)
{
	if (data) {
		memset(data, 0, sizeof(lcsudo_s));
		MALLOC_DATA_MEMBER(com, DOMAIN);
		MALLOC_DATA_MEMBER(domain, DOMAIN);
		MALLOC_DATA_MEMBER(group, GROUP);
		MALLOC_DATA_MEMBER(host, CANAME);
		MALLOC_DATA_MEMBER(rgroup, GROUP);
		MALLOC_DATA_MEMBER(ruser, NAME);
		MALLOC_DATA_MEMBER(user, NAME);
	} else {
		fprintf(stderr, "null pointer passed to init_lcsudo_data_struct");
		exit(1);
	}
}

void
clean_lcsudo_data(lcsudo_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(com);
		CLEAN_DATA_MEMBER(domain);
		CLEAN_DATA_MEMBER(group);
		CLEAN_DATA_MEMBER(host);
		CLEAN_DATA_MEMBER(rgroup);
		CLEAN_DATA_MEMBER(ruser);
		CLEAN_DATA_MEMBER(user);
		free(data);
	}
}

void
check_snprintf(char *target, int max, const char *string, const char *what)
{
	int retval;

	retval = snprintf(target, max, "%s", string);
	if (retval >= max)
		rep_truncate(what, max);
	else if (retval < 0)
		fprintf(stderr, "Output error for %s\n", what);
}

int
add_trailing_slash(char *member)
{
	size_t len;
	int retval;

	retval = 0;
	len = strlen(member);
	if (member[len - 1] != '/') {
		member[len] = '/';
		member[len + 1] = '\0';
	} else if ((member[len - 1] == '/')) {
		retval = NONE;
	} else {
		retval = -1;
	}

	return retval;
}

void
output_version(const char *name)
{
	const char *prog;

	if (!(prog = strrchr(name, '/')))
		prog = name;
	else
		prog++;
	fprintf(stderr, "%s: %s\n", prog, VERSION);
}
