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
 *  base-sha.c
 * 
 *  Contains the sha function for generating passwords for slapd
 *  and also various other functions
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h> 
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "base-sha.h"


void
rep_err(const char *error)
{
	fprintf(stderr, "%s\n", error);
	exit (MEM);
}

int
init_input_data(inp_data_s *data) 
{
	if (!data)
		return ONE;
	data->gr = data->lu = data->user = data->np = NONE;
	data->dom = data->pass = data->sur = data->name = '\0';
	MALLOC_DATA_MEMBER(dom, DOMAIN);
	MALLOC_DATA_MEMBER(pass, DOMAIN);
	MALLOC_DATA_MEMBER(sur, SURNAME);
	MALLOC_DATA_MEMBER(uname, SURNAME);
	MALLOC_DATA_MEMBER(fname, SURNAME);
	MALLOC_DATA_MEMBER(name, USER);
	return NONE;
}

void
clean_data(inp_data_s *data)
{
	if (!data)
		exit (MEM);
	CLEAN_DATA_MEMBER(dom)
	CLEAN_DATA_MEMBER(pass)
	CLEAN_DATA_MEMBER(sur)
	CLEAN_DATA_MEMBER(name)
	CLEAN_DATA_MEMBER(uname)
	CLEAN_DATA_MEMBER(fname)
	free(data);
}

void
split_name(inp_data_s *data)
{
	char *work, *tmp, *pos;
	int c = NONE, len = NONE; /* c counts names */
	unsigned char f = NONE, s = NONE; /* first letter of (f)irst and (s)urname */

	work = strndup(data->name, USERL);
	tmp = work;
	while ((tmp = strchr(tmp, ' '))) {
		c++;
		tmp++;
	}
	tmp = work;
	if (c < 1) {
		fprintf(stderr, "No surname or first name provided\n");
		free(work);
		clean_data(data);
		exit(1);
	} else if (c < 2) { /* No middle name. Wierdo! */
		tmp = strchr(tmp, ' ');
		*tmp = '\0';
		tmp++;
		if ((len = snprintf(data->fname, SURNAME, "%s", work)) > SURNAME)
			fprintf(stderr, "First name truncated by %d!\n",
				(len - SURNAME) + 1);
		if ((len = snprintf(data->sur, SURNAME, "%s", tmp)) > SURNAME)
			fprintf(stderr, "Surname Truncated by %d!\n",
				(len - SURNAME) + 1);
	} else { /* We have a middle name */
		tmp = strchr(tmp, ' ');
		*tmp = '\0';
		tmp++;
		if ((len = snprintf(data->fname, SURNAME, "%s", work)) > SURNAME)
			fprintf(stderr, "First name truncated by %d!\n",
				(len - SURNAME) + 1);
		while ((tmp = strchr(tmp, ' ')))
			pos = ++tmp;
		if ((len = snprintf(data->sur, SURNAME, "%s", pos)) > SURNAME)
			fprintf(stderr, "Surname truncated by %d\n",
				(len = SURNAME) + 1);
	}
	pos = data->sur;
	pos++;
	f = tolower(*(data->fname));
	s = tolower(*(data->sur));
	if (data->lu > NONE) {/* Long format username */
		if ((len = snprintf(data->uname, SURNAME, "%c%c%s",
		 f, s, pos)) > SURNAME)
			fprintf(stderr, "Username truncated by %d!\n",
				(len - SURNAME) + 1);
	} else {
		pos = data->fname;
		pos++;
		if ((len = snprintf(data->uname, SURNAME, "%c%s",
		 f, pos)) > SURNAME)
			fprintf(stderr, "Username truncated by %d!\n",
				(len - SURNAME) + 1);
	}
	free(work);
}

int
parse_command_line(int argc, char *argv[], inp_data_s *data)
{
	int opt = NONE, slen = NONE;

	while ((opt = getopt(argc, argv, "d:gln:pu:")) != -1) {
		if (opt == 'd') {
			GET_OPT_ARG(dom, DOMAIN, Domain)
		} else if (opt == 'g') {
			data->gr = ONE;
		} else if (opt == 'l') {
			data->lu = ONE;
		} else if (opt == 'p') {
			data->np = ONE;
		} else if (opt == 'n') {
			GET_OPT_ARG(name, USER, Name)
		} else if (opt == 'u') {
			if (optarg)
				data->user = (short)strtoul(optarg, NULL, DECIMAL);
			else
				fprintf(stderr, "No userid specified\n");
		} else {
			comm_line_err(argv[0]);
			return ONE;
		}
	}
	if (strlen(data->dom) == 0) {
		fprintf(stderr, "No domain specified\n");
		comm_line_err(argv[0]);
		exit (1);
	} else if (strlen(data->name) == 0) {
		fprintf(stderr, "No name specified\n");
		comm_line_err(argv[0]);
		exit (1);
	} else if (data->user == 0) {
		fprintf(stderr, "No userid specified\n");
		comm_line_err(argv[0]);
		exit (1);
	}
	return NONE;
}

char *
getPassword(const char *message)
{
	static struct termios oldt, newt;
	int i = 0;
	int c;
	char *pass;

	if (!(pass = malloc(PASS_SIZE)))
		exit (2);
	fprintf(stderr, "%s", message);
	/*saving the old settings of STDIN_FILENO and copy settings for resetting*/
	tcgetattr( STDIN_FILENO, &oldt);
	newt = oldt;

	/*setting the approriate bit in the termios struct*/
	newt.c_lflag &= ~(ECHO);  

	/*setting the new bits*/
	tcsetattr( STDIN_FILENO, TCSANOW, &newt);

	/*reading the password from the console*/
	while ((c = getchar())!= '\n' && c != EOF && i < (PASS_SIZE - 1))
		pass[i++] = c;
	pass[i] = '\0';

	/*resetting our old STDIN_FILENO*/ 
	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
	fprintf(stderr, "\n");
	return pass;
}

void
comm_line_err(char *prog)
{
	fprintf(stderr, "\
Usage: %s -d domain [ -g ] [ -l ] [ -p ] -n full-name -u userid\n\
-g: create group for the user (same name and id)\n\
-l: create long user name (first initial plus surname)\n\
-p: do not ask for a password\n", prog);
}

void
output_ldif(inp_data_s *data)
{
	char *name, *ldom, *phash = '\0';

	ldom = get_ldif_domain(data->dom);
/*	name = get_ldif_user(data); */
	name = data->uname;
	if (data->np ==  0)
		phash = get_ldif_pass_hash(data->pass);
	*(data->sur) = toupper(*(data->sur));
	printf("\
# %s, people, %s\n\
dn: uid=%s,ou=people,%s\n\
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
", name, data->dom, name, ldom, name, data->sur, data->fname, data->name, 
data->user, name);
	if (data->np == 0)
		printf("userPassword: {SSHA}%s\n", phash);
	*(data->name) = toupper(*(data->name));
	printf("gecos: %s\n", data->name);
	*(data->name) = tolower(*(data->name));
	printf("mail: %s@%s\n", name, data->dom);
	if (data->gr > NONE)
		printf("\
gidNumber: %hd\n\
\n\
# %s, group, %s\n\
dn: cn=%s,ou=group,%s\n\
cn: %s\n\
gidNumber: %hd\n\
objectClass: posixGroup\n\
objectClass: top\n\
", data->user, name, data->dom, name, ldom, name, data->user);
	else
		printf("\
gidNumber: 100\n\
\n\
");
	free(name);
	free(ldom);
	if (phash)
		free(phash);
}

char *
get_ldif_domain(char *dom)
{
	char *ldom, *tmp, *save, *empty = '\0', *buff, *domain;
	const char *delim = ".";
	int c = NONE;
	size_t len = NONE;

	if (!(buff = malloc(DOMAIN)))
		rep_err("buff in get_ldif_domain");
	len = strlen(dom);
	if (!(domain = calloc((len + 1), sizeof(char))))
		rep_err("domain in get_ldif_domain");
	strncpy(domain, dom, len);
	tmp = domain;
	while ((tmp = strchr(tmp, '.'))) {
		tmp++;
		c++;
	}
	len = strlen(dom) + (size_t)(c * 3);
	if (len >= DOMAIN) {
		if(!(ldom = malloc(BUFF))) {
			rep_err("ldom in get_ldif_domain");
		}
	} else {
		if (!(ldom = malloc(DOMAIN))) {
			rep_err("ldom in get_ldif_domain");
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
		rep_err("name in get_ldif_user");
	*(data->sur) = tolower(*(data->sur));
	if (data->lu > 0)
		sprintf(name, "%c%s", *(data->name), data->sur);
	else
		sprintf(name, "%s", data->name);
	return name;
}

char *
get_ldif_pass_hash(char *pass)
{
	int rd = open("/dev/urandom", O_RDONLY), i;
	char *npass, salt[6], type[] = "sha1";
	guchar *out;
        EVP_MD_CTX *msg;
        const EVP_MD *md;
        unsigned int md_len;

	if (!(out = malloc(26)))
		rep_err("out in get_ldif_pass_hash");
	if ((read(rd, &salt, 6)) != 6) {
		close(rd);
		rep_err("Could not read enough random data");
	}
	close(rd);
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(type);
        if (!md) {
                printf("Unknown digest %s!\n", type);
                exit(1);
        }
	msg = EVP_MD_CTX_create();
	EVP_DigestInit_ex(msg, md, NULL);
	EVP_DigestUpdate(msg, pass, strlen(pass));
	EVP_DigestUpdate(msg, salt, 6);
	EVP_DigestFinal_ex(msg, out, &md_len);
	EVP_MD_CTX_destroy(msg);
	EVP_cleanup();
	for (i = 0; i < 6; i++)
		*(out + 20 + i) = salt[i];
	npass = g_base64_encode(out, 26);
	free(out);
	return npass;
}

/*
int
hex_conv(const char *pass, guchar *out)
{
	int retval = NONE;
	gsize olen = strlen(out), x;
	for (x = 0; x < olen; x++) {
		sscanf(pass + 2*x, "%02x", &out[x]);
	}
	return retval;
}
*/
