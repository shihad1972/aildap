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
 *  base-sha.h
 *
 *  Contains the sha function definitions for generating passwords for slapd
 *  and also various other functions
 *
 */

#ifndef HAVE_BASE_H
# define HAVE_BASE_H
# include <glib.h>

enum {
	NONE = 0,
	ONE = 1,
	DECIMAL = 10,
	SURNAMEL = 31,
	SURNAME= 32,
	USERL = 127,
	USER = 128,
	DOMAIN = 256,
	MEM = 300,
	BUFF = 512
};

typedef struct inp_data_s {
	unsigned short int gr, lu, user, np;
	char *dom, *sur, *name, *uname, *pass, *fname;
} inp_data_s;

#ifndef MALLOC_DATA_MEMBER
# define MALLOC_DATA_MEMBER(mem, SIZE) {                            \
	if (!(data->mem = calloc(ONE, SIZE)))                       \
		rep_err("Cannot malloc mem");                       \
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

char *
getPassword(const char *message);

void
rep_err(const char *error);

int
init_input_data(inp_data_s *data);

void
clean_data(inp_data_s *data);

void
split_name(inp_data_s *data);

int
parse_command_line(int argc, char *argv[], inp_data_s *data);

void
comm_line_err(char *prog);

void
output_ldif(inp_data_s *data);

char *
get_ldif_domain(char *domain);

char *
get_ldif_user(inp_data_s *data);

char *
get_ldif_pass_hash(char *pass);

int
hex_conv(const char *pass, guchar *out);

#endif /* HAVE_BASE_H */
