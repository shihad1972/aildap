/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2023  Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  ldif.c
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

static int
get_delim(const char *delim);

static int
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

char *
get_ldif_domain(const char *dom)
{
	char *ldom, *tmp, *save, *buff, *domain;
	const char *delim = ".";
	int c = NONE;
	size_t len = NONE;

	if (!(dom))
		return '\0';
	if (!(buff = malloc(DOMAIN)))
		error(MALLOC, errno, "buff in get_ldif_domain");
	len = strlen(dom);
	if (!(domain = calloc((len + 1), sizeof(char))))
		error(MALLOC, errno, "domain in get_ldif_domain");
	strcpy(domain, dom); // should not have to do this to silence compiler warnings
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

