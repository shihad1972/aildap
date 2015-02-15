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
 *  ldap-col.h
 *
 *  Data header file for the various ldap collection  program. This contains 
 *  the typedefs for the structs and also various funciton definitions
 *
 *  Part of the ldap collection suite of program
 *
 *  (C) Iain M Conochie 2014 */

#ifndef HAVE_LDAP_COL_H
# define HAVE_LDAP_COL_H

void
rep_error(const char *error);

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
	short int file;
} lcdb_s;

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
	unsigned short int gr, lu, user, np;
	char *dom, *sur, *name, *uname, *pass, *fname;
} inp_data_s;

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
	FILE_O_FAIL = 16,
	GROUP = 16,
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
	SURNAME= 32,
	USERL = 127,
	USER = 128,
	MEM = 300,
	BUFF = 512,
	BBUFF = 1024
};

#ifndef MALLOC_DATA_MEMBER
# define MALLOC_DATA_MEMBER(mem, SIZE) {                            \
	if (!(data->mem = calloc(ONE, SIZE)))                       \
		rep_error("Cannot malloc data->mem");               \
}
#endif /* MALLOC_DATA_MEMBER */

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

#ifndef GET_OPT_ARG
# define GET_OPT_ARG(member, LEN, Name) {                                     \
	if ((slen = snprintf(data->member, LEN, "%s", optarg)) > LEN) {       \
		fprintf(stderr, "Name truncated by %d\n", (slen - LEN) + 1);  \
	}                                                                     \
}
#endif /* GET_OPT_ARG */

#define PASS_SIZE 100

void
rep_error(const char *error);

void
resize_string_buff(string_len_s *build);

void
init_string_len(string_len_s *build);

void
clean_string_len(string_len_s *string);

void
rep_usage(const char *prog);

void
rep_truncate(const char *what, int max);

void
init_lcr_data_struct(lcr_t *data);

void
clean_lcr_data_struct(lcr_t *data);

void
init_lgc_data_struct(lgc_s *data);

void
clean_lgc_data(lgc_s *data);

void
init_lck_data_struct(lck_s *data);

void
clean_lck_data_struct(lck_s *data);

void
init_lcou_data_struct(lcou_s *data);

void
clean_lcou_data_struct(lcou_s *data);

void
init_lcs_data_struct(cert_s *data);

void
clean_lcs_data(cert_s *data);

int
init_lcu_data(inp_data_s *data);

void
clean_lcu_data(inp_data_s *data);

void
init_lcdb_data_struct(lcdb_s *data);

void
clean_lcdb_data(lcdb_s *data);

void
init_lcc_data_struct(cont_s *data);

void
clean_lcc_data(cont_s *data);

void
init_lcsudo_data_struct(lcsudo_s *data);

void
clean_lcsudo_data(lcsudo_s *data);

char *
get_ldif_domain(char *domain);

char *
get_ldif_format(char *ou, const char *type, const char *delim);

char *
get_ldif_user(inp_data_s *data);

int
get_delim(const char *delim);

void
check_snprintf(char *target, int max, const char *string, const char *what);

int
add_trailing_slash(char *member);
#endif /* HAVE_LDAP_COL_H */
