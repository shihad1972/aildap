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

typedef struct lrc_t {
	char *host, *domain, *user, *db, *cdb, *ca;
	short int ssl, tls, file;
} lrc_t;

typedef struct string_len_s {
	char *string;
	size_t len;
	size_t size;
} string_len_s;

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
	FILE_O_FAIL = 16,
	NAME = 32,
	DC = 64,
	DNL = 67,
	DOMAIN = 256,
	DN = 512,
	FILES = 4096
};

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

#endif /* HAVE_LDAP_COL_H */