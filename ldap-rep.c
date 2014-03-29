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
 *  (C) Iain M Conochie 2014 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "ldap-col.h"

void
rep_error(const char *error)
{
	fprintf(stderr, "Cannot allocate memory for %s\n", error);
	exit(MALLOC);
}

void
resize_string_buff(string_len_s *build)
{
	char *tmp;

	build->len *=2;
	tmp = realloc(build->string, build->len * sizeof(char));
	if (!tmp)
		rep_error("tmp in resize_string_buff");
	else
		build->string = tmp;
}

void
init_string_len(string_len_s *build)
{
	build->len = FILES;
	build->size = NONE;
	if (!(build->string = calloc(build->len, sizeof(char))))
		rep_error("build->string in init_string_len");
}

void
clean_string_len(string_len_s *string)
{
	if (string) {
		if (string->string)
			free(string->string);
		free(string);
	}
}

void
rep_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s ", prog);
	if (strstr(prog, "lcr")) 
		fprintf(stderr, "-d domain -h host -u user\
 -b db# -r db# [ -f ] [ -s | -t ] [ -c ca-cert]\n");
	else if (strstr(prog, "lcg"))
		fprintf(stderr, " -d domain-name -g gid -n group\
 [ -u user1,user2,...,userN ]\n");
	else if (strstr(prog, "lcdb"))
		fprintf(stderr, " -a admin-user -d domain [ -p path ] [ -f ]\n");
}

void
rep_truncate(const char *what, int max)
{
	fprintf(stderr, "%s truncated. Max allowed is %d\n", what, max - 1);
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
	}else {
		fprintf(stderr, "null pointer passed to init_lgc_data_struct\n");
		exit(1);
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
		MALLOC_DATA_MEMBER(phash, NAME);
		MALLOC_DATA_MEMBER(pass, NAME);
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
init_lcc_data_struct(cont_s *data)
{
	if (data) {
		memset(data, 0, sizeof(cont_s));
		MALLOC_DATA_MEMBER(domain, DOMAIN);
		MALLOC_DATA_MEMBER(dc, DC);
		MALLOC_DATA_MEMBER(dn, DN);
	} else {
		fprintf(stderr, "null pointer passed to init_lcc_data_struct\n");
		exit(1);
	}
}

void
clean_lcc_data(cont_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(domain);
		CLEAN_DATA_MEMBER(dc);
		CLEAN_DATA_MEMBER(dn);
		free(data);
	}
}

char *
get_ldif_domain(char *dom)
{
	char *ldom, *tmp, *save, *empty = '\0', *buff, *domain;
	const char *delim = ".";
	int c = NONE;
	size_t len = NONE;

	if (!(buff = malloc(DOMAIN)))
		rep_error("buff in get_ldif_domain");
	len = strlen(dom);
	if (!(domain = calloc((len + 1), sizeof(char))))
		rep_error("domain in get_ldif_domain");
	strncpy(domain, dom, len);
	tmp = domain;
	while ((tmp = strchr(tmp, '.'))) {
		tmp++;
		c++;
	}
	len = strlen(dom) + (size_t)(c * 3);
	if (len >= DOMAIN) {
		if(!(ldom = malloc(BUFF))) {
			rep_error("ldom in get_ldif_domain");
		}
	} else {
		if (!(ldom = malloc(DOMAIN))) {
			rep_error("ldom in get_ldif_domain");
		}
	}
	tmp = strtok_r(domain, delim, &save);
	sprintf(ldom, "dc=%s", tmp);
	while ((tmp = strtok_r(empty, delim, &save))) {
		sprintf(buff, ",dc=%s", tmp);
		strcat(ldom, buff);
	}
	free(buff);
	free(domain);
	return ldom;
}

char *
get_ldif_user(inp_data_s *data)
{
	char *name;

	if (!(name = malloc(USER)))
		rep_error("name in get_ldif_user");
	*(data->sur) = tolower(*(data->sur));
	if (data->lu > 0)
		sprintf(name, "%c%s", *(data->name), data->sur);
	else
		sprintf(name, "%s", data->name);
	return name;
}

void
check_snprintf(char *target, int max, const char *string, const char *what)
{
	int retval;

	retval = snprintf(target, max, "%s", string);
	if (retval > max)
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
