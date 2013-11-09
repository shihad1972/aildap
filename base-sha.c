/*
 * base-sha.c: (C) 2013 Iain M Conochie
 * 
 * Library functions for the program to create user entries in the ldap
 * directory. 
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
	data->gr = data->lu = data->user = NONE;
	data->dom = data->pass = data->sur = data->name = '\0';
	MALLOC_DATA_MEMBER(dom, DOMAIN);
	MALLOC_DATA_MEMBER(pass, DOMAIN);
	MALLOC_DATA_MEMBER(sur, SURNAME);
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
	free(data);
}

int
parse_command_line(int argc, char *argv[], inp_data_s *data)
{
	int opt = NONE, slen = NONE;

	while ((opt = getopt(argc, argv, "d:gln:s:u:")) != -1) {
		if (opt == 'd') {
			GET_OPT_ARG(dom, DOMAIN, Domain)
		} else if (opt == 'g') {
			data->gr = ONE;
		} else if (opt == 'l') {
			data->lu = ONE;
		} else if (opt == 'n') {
			GET_OPT_ARG(name, USER, Name)
		} else if (opt == 's') {
			GET_OPT_ARG(sur, SURNAME, Surname)
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
	} else if (strlen(data->sur) == 0) {
		fprintf(stderr, "No surname specified\n");
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
	printf("%s", message);
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
	printf("\n");
	pass[i] = '\0';

	/*resetting our old STDIN_FILENO*/ 
	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
	return pass;
}

void
comm_line_err(char *prog)
{
	fprintf(stderr, "\
Usage: %s -d domain [ -g ] [ -l ] -n name -s surname -u userid\n\
-g: create group for the user (same name and id)\n\
-l: create long user name (first initial plus surname\n", prog);
}

void
output_ldif(inp_data_s *data)
{
	char *name, *ldom, *phash;

	ldom = get_ldif_domain(data->dom);
	name = get_ldif_user(data);
	phash = get_ldif_pass_hash(data->pass);
	*(data->sur) = toupper(*(data->sur));
	printf("\
# %s, people, %s\n\
dn: uid=%s,ou=people,%s\n\
uid: %s\n\
sn: %s\n\
objectClass: inetOrgPerson\n\
objectClass: posixAccount\n\
objectClass: top\n\
objectClass: shadowAccount\n\
shadowLastChange: 0\n\
shadowMax: 99999\n\
shadowWarning: 7\n\
loginShell: /bin/bash\n\
uidNumber: %hd\n\
userPassword: {SSHA}%s\n\
homeDirectory: /home/%s\n\
", name, data->dom, name, ldom, name, data->sur, data->user
, phash, name);
	*(data->name) = toupper(*(data->name));
	printf("gecos: %s %s\n", data->name, data->sur);
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
	char *npass, salt[6], type[] = "sha";
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
