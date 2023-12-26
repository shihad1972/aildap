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
 *  ailsaldap.h
 *
 *  Data header file for the various ailsa ldap library. This contains 
 *  the typedefs for the structs and also various funciton definitions
 *
 *  Part of the ldap collection suite of program
 *
 */

#include <ldap.h>
#include <ailsa.h>

#ifndef HAVE_AILSA_LDAP_H
# define HAVE_AILSA_LDAP_H

typedef struct lcr_t {
	char *host, *domain, *user, *pass, *db, *cdb, *pdb, *ca;
	short int ssl, tls, file, cons, prov, mod;
} lcr_t;

typedef struct lcg_s {
	char *domain, *dc, *dn, *name, *user;
	short int group;
} lgc_s;

typedef struct lck_s {
	char *host, *realm;
	short int file;
} lck_s;

typedef struct lcou_s {
	char *domain, *newou, *ou;
	short int file, action;
} lcou_s;

typedef struct lcsudo_s {
	char *domain, *user, *group, *host, *com, *ruser, *rgroup;
	short int file, action;
} lcsudo_s;

typedef struct lcdb_s {
	char *domain, *admin, *pass, *phash, *dir;
	short int file, type;
} lcdb_s;

typedef struct lcdhcp_s {
	const char *bfile, *bserver, *ether, *ddns, *dn, *domain;
	const char *gw, *ipaddr, *name, *netb, *netm, *ou, *filename;
	short int action, boot;
} lcdhcp_s;

typedef struct cert_s {
	char *hostname, *ca;
	short int action;
} cert_s;

typedef struct string_len_s {
	char *string;
	size_t len;
	size_t size;
} string_len_s;

typedef struct cont_s {
	char *domain, *dc, *dn;
	short int action, sudo, file;
} cont_s;

typedef struct inp_data_s {
	unsigned short int gr, lu, user, np, sso;
	char *dom, *sur, *name, *uname, *pass, *fname, *gou, *uou;
} inp_data_s;

/*
 * Attempt to declare and define this in a header file.
 *
 * See:
 * http://stackoverflow.com/questions/1433204/how-do-i-use-extern-to-share-variables-between-source-files-in-c
 *
 * As this is a const, should be safe that every file that includes this
 * get's it's own copy of the variable
 *
 * Wrapping in a #define to ensure only programs that want it will get it
 * exposed. Otherwise, we get unused varaible compiler warnings.
 */
# ifdef WANT_OBCL_TOP
static const char *obcl_top = "objectClass: top";
# endif // WANT_OBCL_TOP

enum {
	NONE = 0,
	ONE,
	MALLOC,
	WARG,
	NODOM,
	NOGRP,
	NOGRNM,
	NODATA,
	DB = 8,
	INSERT,
	REMOVE,
	DOMLONG,
	CALONG,
	NOOU,
	MODIFY,
	NOTYPE,
	CONF_USER,
	CONF_URL,
	CONF_PASS,
	CONF_BASE_DN,
	CONF_FILTER,
	FILE_O_FAIL = 16,
	GROUP = 16,
	TRUNC = 17,
	NAME = 32,
	DC = 64,
	CANAME = 64,
	DNL = 67,
	DOMAIN = 256,
	DN = 512,
	FILES = 4096
};

enum {
	DECIMAL = 10,
	SURNAMEL = 31,
	SURNAME = 32,
	USERL = 127,
	USER = 128,
	MEM = 300,
	BUFF = 512,
	BBUFF = 1024
};

enum {
	HDB = 1,
	MDB = 2
};

enum {
	ACT_HELP = 1,
	ACT_VERSION = 2
};

#ifndef MALLOC_DATA_MEMBER
# define MALLOC_DATA_MEMBER(mem, SIZE) {                            \
	if (!(data->mem = calloc(ONE, SIZE)))                       \
		error(MALLOC, errno, "data->mem");                  \
}
#endif /* MALLOC_DATA_MEMBER */

#ifndef CLEAN_DATA_MEMBER
# define CLEAN_DATA_MEMBER(mem) {                                   \
	if (data->mem) {                                            \
		free(data->mem);                                    \
		data->mem = NULL;                                   \
	}                                                           \
}
#endif /* CLEAN_DATA_MEMBER */

#define PASS_SIZE 100

void
rep_usage(const char *prog);

void
rep_truncate(const char *what, int max);

int
init_lcu_data(inp_data_s *data);

void
clean_lcu_data(inp_data_s *data);

void
init_lcr_data_struct(lcr_t *data);

void
clean_lcr_data_struct(lcr_t *data);

void
init_lgc_data_struct(lgc_s *data);

void
init_lck_data_struct(lck_s *data);

void
clean_lck_data_struct(lck_s *data);

void
init_lcou_data_struct(lcou_s *data);

void
clean_lcou_data_struct(lcou_s *data);

void
clean_lgc_data(lgc_s *data);

void
init_lcdb_data_struct(lcdb_s *data);

void
clean_lcdb_data(lcdb_s *data);

void
init_lcc_data_struct(cont_s *data);

void
clean_lcc_data(cont_s *data);

void
init_lcs_data_struct(cert_s *data);

void
clean_lcs_data(cert_s *data);

void
init_lcsudo_data_struct(lcsudo_s *data);

void
clean_lcsudo_data(lcsudo_s *data);

char *
get_ldif_format(const char *form, const char *type, const char *delim);

char *
get_ldif_user(inp_data_s *data);

void
check_snprintf(char *target, int max, const char *string, const char *what);

int
add_trailing_slash(char *member);

char *
getPassword(const char *message);

void
rep_err(const char *error);

void
split_name(inp_data_s *data);

void
output_user_ldif(inp_data_s *data);

void
output_sso_ldif(inp_data_s *data);

void
output_version(const char *name);

void
aildap_parse_config(AILSA_LIST *config, const char *prog);

# ifdef HAVE_OPENSSL
char *
get_ldif_pass_hash(char *pass);

unsigned char *
ailsa_hash_string(char *string, const char *type);

int
output_hex_conversion(unsigned char *string, const char *hash);

# endif //HAVE_OPENSSL

// LDAP Helper functions
void
ailsa_ldap_init(LDAP **ailsa, const char *url);

#endif // HAVE_AILSA_LDAP_H
