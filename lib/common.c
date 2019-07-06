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
resize_string_buff(string_len_s *build)
{
	char *tmp;

	build->len *=2;
	tmp = realloc(build->string, build->len * sizeof(char));
	if (!tmp)
		error(MALLOC, errno, "tmp in resize_string_buff");
	else
		build->string = tmp;
}

void
init_string_len(string_len_s *build)
{
	build->len = FILES;
	build->size = NONE;
	if (!(build->string = calloc(build->len, sizeof(char))))
		error(MALLOC, errno, "build->string in init_string_len");
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
-d domain [ -g ] [ -l ] [ -p ] -n full-name -u userid\n\
-g: create group for the user (same name and id)\n\
-l: create long user name (first initial plus surname)\n");
#ifdef HAVE_OPENSSL
		fprintf(stderr, "\
-p: do not ask for a password\n");
#endif /* HAVE_OPENSSL */
	} else if (strstr(prog, "hh")) {
		fprintf(stderr, "[ -n hostname ]\n");
	}
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
init_lcou_data_struct(lcou_s *data)
{
	if (data) {
		memset(data, 0, sizeof(lcou_s));
		MALLOC_DATA_MEMBER(domain, DOMAIN);
		MALLOC_DATA_MEMBER(newou, CANAME);
		MALLOC_DATA_MEMBER(ou, CANAME);
	} else {
		fprintf(stderr, "null pointer passed to init_lcu_data_struct\n");
		exit(1);
	}
}

void
clean_lcou_data_struct(lcou_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(domain);
		CLEAN_DATA_MEMBER(newou);
		CLEAN_DATA_MEMBER(ou);
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
init_lcdhcp_data_struct(lcdhcp_s *data)
{
	if (data) {
		memset(data, 0, sizeof(lcdhcp_s));
		data->boot = 1;
	} else {
		fprintf(stderr, "null pointer passed to init_lcdhcp_data_struct");
		exit(1);
	}
}

void
clean_lcdhcp_data(lcdhcp_s *data)
{
	if (data) {
		CLEAN_DATA_MEMBER(basedn);
		CLEAN_DATA_MEMBER(bfile);
		CLEAN_DATA_MEMBER(bserver);
		CLEAN_DATA_MEMBER(ether);
		CLEAN_DATA_MEMBER(cont);
		CLEAN_DATA_MEMBER(ddns);
		CLEAN_DATA_MEMBER(dn);
		CLEAN_DATA_MEMBER(domain);
		CLEAN_DATA_MEMBER(gw);
		CLEAN_DATA_MEMBER(ipaddr);
		CLEAN_DATA_MEMBER(name);
		CLEAN_DATA_MEMBER(netb);
		CLEAN_DATA_MEMBER(netm);
		CLEAN_DATA_MEMBER(ou);
		CLEAN_DATA_MEMBER(filename);
		free(data);
	}
}

char *
get_ldif_domain(char *dom)
{
	char *ldom, *tmp, *save, *buff, *domain;
	const char *delim = ".";
	int c = NONE;
	size_t len = NONE;

	if (!(buff = malloc(DOMAIN)))
		error(MALLOC, errno, "buff in get_ldif_domain");
	len = strlen(dom);
	if (!(domain = calloc((len + 1), sizeof(char))))
		error(MALLOC, errno, "domain in get_ldif_domain");
	strncpy(domain, dom, len);
	tmp = domain;
	while ((tmp = strchr(tmp, '.'))) {
		tmp++;
		c++;
	}
	len = strlen(dom) + (size_t)(c * 3);
	if (len >= DOMAIN) {
		if(!(ldom = malloc(BUFF))) {
			error(MALLOC, errno, "ldom in get_ldif_domain");
		}
	} else {
		if (!(ldom = malloc(DOMAIN))) {
			error(MALLOC, errno, "ldom in get_ldif_domain");
		}
	}
	tmp = strtok_r(domain, delim, &save);
	sprintf(ldom, "dc=%s", tmp);
	while ((tmp = strtok_r(NULL, delim, &save))) {
		sprintf(buff, ",dc=%s", tmp);
		strcat(ldom, buff);
	}
	free(buff);
	free(domain);
	return ldom;
}

char *
get_ldif_format(char *form, const char *type, const char *delim)
{
/*
 * Take delim separated string (form), and turn into an ldif farmat string.
 * Base on type (dc, ou , o etc) so can have multiple elements.
 *
 * e.g. foo,bar,you,me ou -> ou=foo,ou=bar,ou=you,ou=me
 * or my.sub.domain.com dc -> dc=my,dc=sub,dc=domain,dc=com
 */
	char *ldom, *tmp, *save, *buff, *work;
	int i = 1, c;
	size_t len = NONE;

	if (!(form) || !(type))
		return NULL;
	if ((c = get_delim(delim)) == 0)
		return NULL;
	if ((len = strlen(form)) == 0)
		return NULL;
	work = strndup(form, len);
	tmp = work;
	while ((tmp = strchr(tmp, c))) {
		i++;
		tmp++;
	}
	len = len + (size_t)(i * 3) + 1;
	if (!(ldom = calloc(len, sizeof(char))))
		error(MALLOC, errno, "ldom in get_ldif_format");
	if (!(buff = malloc(BUFF)))
		error(MALLOC, errno, "buff in get_ldif_format");
	tmp = strtok_r(work, delim, &save);
	sprintf(ldom, "%s=%s", type, tmp);
	while ((tmp = strtok_r(NULL, delim, &save))) {
		sprintf(buff, ",%s=%s", type, tmp);
		strcat(ldom, buff);
	}
	free(buff);
	free(work);
	return ldom;
}


char *
get_ldif_user(inp_data_s *data)
{
	char *name;

	if (!(name = malloc(USER)))
		error(MALLOC, errno, "name in get_ldif_user");
	*(data->sur) = tolower(*(data->sur));
	if (data->lu > 0)
		sprintf(name, "%c%s", *(data->name), data->sur);
	else
		sprintf(name, "%s", data->name);
	return name;
}

int
get_delim(const char *delim)
{
	if (strncmp(".", delim, 2) == 0)
		return '.';
	else if (strncmp(",", delim, 2) == 0)
		return ',';
	else if (strncmp(":", delim, 2) == 0)
		return ':';
	else if (strncmp(";", delim, 2) == 0)
		return ';';
	else
		return 0;
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

