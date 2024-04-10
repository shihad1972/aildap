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
get_ldif_format(const char *form, const char *type, const char *delim)
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

void
output_sso_ldif(inp_data_s *data)
{
	char *name, *ldom = get_ldif_format(data->dom, "dc", ".");
	unsigned char *phash = NULL;
	const char *uou = "people";

	name = data->name;
	if (data->uou)
		uou = data->uou;
	if (data->np ==  0)
		phash = ailsa_get_pass_hash(data->pass, "sha1", strlen(data->pass));
	printf("\
# %s, %s, %s\n\
dn: cn=%s,ou=%s,%s\n\
cn: %s\n\
objectClass: simpleSecurityObject\n\
objectClass: organizationalRole\n", name, uou, ldom, name, uou, ldom, name);
	if (data->np == 0)
		// The below gives errors in debian package build. Probably due to ifdefs
		printf("userPassword: {SSHA}%s\n", phash);
	free(ldom);
	if(phash)
		free(phash);
}

void
output_user_ldif(inp_data_s *data)
{
	char *name, *ldom;
	const char *uou = "people", *gou = "group";
	unsigned char *phash = NULL;

	ldom = get_ldif_format(data->dom, "dc", ".");
	name = data->uname;
	if (data->uou)
		uou = data->uou;
	if (data->gou)
		gou = data->gou;
	if (data->np ==  0)
		phash = ailsa_get_pass_hash(data->pass, "sha1", strlen(data->pass));
	*(data->sur) = toupper(*(data->sur));
	printf("\
# %s, people, %s\n\
dn: uid=%s,ou=%s,%s\n\
uid: %s\n\
sn: %s\n\
gn: %s\n\
cn: %s\n\
objectClass: inetOrgPerson\n\
objectClass: posixAccount\n\
objectClass: top\n\
objectClass: shadowAccount\n\
shadowLastChange: 0\n\
shadowMax: 99999\n\
shadowWarning: 7\n\
loginShell: /bin/bash\n\
uidNumber: %hd\n\
homeDirectory: /home/%s\n\
", name, data->dom, name, uou, ldom, name, data->sur, data->fname, data->name, 
data->user, name);
	if (data->np == 0)
		printf("userPassword: {SSHA}%s\n", phash);
	printf("gecos: %s %s\n", data->fname, data->sur);
	printf("mail: %s@%s\n", name, data->dom);
	if (data->gr > NONE)
		printf("\
gidNumber: %hd\n\
\n\
# %s, group, %s\n\
dn: cn=%s,ou=%s,%s\n\
cn: %s\n\
gidNumber: %hd\n\
objectClass: posixGroup\n\
objectClass: top\n\
", data->user, name, data->dom, name, gou, ldom, name, data->user);
	else
		printf("\
gidNumber: 100\n\
\n\
");
	free(ldom);
	if (phash)
		free(phash);
}

