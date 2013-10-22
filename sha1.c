#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

enum {
	NONE = 0,
	ONE = 1,
	DECIMAL = 10,
	SURNAME= 31,
	USER = 32,
	DOMAIN = 256,
	MEM = 300
};

typedef struct inp_data_s {
	unsigned short int gr, lu, user;
	char *dom, *pass, *sur, *name;
} inp_data_s;

#ifndef MALLOC_DATA_MEMBER
# define MALLOC_DATA_MEMBER(mem, SIZE) {                            \
	if (!(data->mem = calloc(ONE, SIZE)))                       \
		rep_err("Cannot malloc mem");                       \
}
#endif /* MALLOC_DATA_MEMBER */

void
rep_err(const char *error)
{
	fprintf(stderr, "%s\n", error);
	exit (MEM);
}

int
init_input_data(inp_data_s *data) {

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

#ifndef CLEAN_DATA_MEMBER
# define CLEAN_DATA_MEMBER(mem) {                                   \
	if (data->mem) {                                            \
		free(data->mem);                                    \
	} else {                                                    \
		fprintf(stderr, "data->mem does not exist??\n");    \
		exit (MEM);                                         \
	}                                                           \
}
#endif /* CLEAN_DATA_MEMBER */

void
clean_data(inp_data_s *data) {

	if (!data)
		exit (MEM);
	CLEAN_DATA_MEMBER(dom)
	CLEAN_DATA_MEMBER(pass)
	CLEAN_DATA_MEMBER(sur)
	CLEAN_DATA_MEMBER(name)
}

#ifndef GET_OPT_ARG
# define GET_OPT_ARG(member, LEN, Name) {                                     \
	if ((slen = snprintf(data->member, LEN, "%s", optarg)) > LEN) {       \
		fprintf(stderr, "Name truncated by %d\n", (slen - LEN) + 1);  \
	}                                                                     \
}
#endif /* GET_OPT_ARG */

int
parse_command_line(int argc, char *argv[], inp_data_s *data)
{
	int opt = NONE, slen = NONE;

	while (getopt(argc, argv, "d:gln:p:s:u") != -1) {
		if (opt == 'd') {
			GET_OPT_ARG(dom, DOMAIN, Domain)
		} else if (opt == 'g') {
			data->gr = ONE;
		} else if (opt == 'l') {
			data->lu = ONE;
		} else if (opt == 'n') {
			GET_OPT_ARG(name, USER, Name)
		} else if (opt == 'p') {
			GET_OPT_ARG(pass, USER, Password)
		} else if (opt == 's') {
			GET_OPT_ARG(sur, SURNAME, Surname)
		} else if (opt == 'u') {
			data->user = (short)strtoul(optarg, NULL, DECIMAL);
		} else {
			fprintf(stderr, "\
Usage: %s -d domain [ -g ] [ -l ] -n name -p password -s surname -u userid\n\
-g: create group for the user (same name and id)\n\
-l: create long user name (first initial plus surname\n", argv[0]);
			return ONE;
		}
	}
	return NONE;
}

int
/*main (int argc, char *argv[]) */
main ()
{
	BIO *bio, *b64;
	EVP_MD_CTX *msg;
	const EVP_MD *md;
	char mess[] = "MyPa55w0rd";
	char type[] = "sha";
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(type);
	if (!md) {
		printf("Unknown digest %s!\n", type);
		exit(1);
	}
	msg = EVP_MD_CTX_create();
	EVP_DigestInit_ex(msg, md, NULL);
	EVP_DigestUpdate(msg, mess, strlen(mess));
	EVP_DigestFinal_ex(msg, md_value, &md_len);
	EVP_MD_CTX_destroy(msg);
	BIO_write(bio, md_value, SHA_DIGEST_LENGTH);
	if (BIO_flush(bio) == ONE) {
		;
	}
	BIO_free_all(bio);

	return 0;
}

#undef MALLOC_DATA_MEMBER
#undef GET_OPT_ARG
#undef CLEAN_DATA_MEMBER