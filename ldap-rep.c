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
 *  ldap-rep.c
 *
 *  Data header file for the various ldap collection  program. This contains 
 *  the typedefs for the structs and also various funciton definitions
 *
 *  Part of the ldap collection suite of program
 *
 *  (C) Iain M Conochie 2014 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"

void
rep_error(const char *error)
{
	fprintf(stderr, "Cannot allocate memory for %s\n", error);
	exit(MALLOC);
}

void
resize_string_buff(string_len_s *build)
{
	char *tmp;

	build->len *=2;
	tmp = realloc(build->string, build->len * sizeof(char));
	if (!tmp)
		rep_error("tmp in resize_string_buff");
	else
		build->string = tmp;
}

void
init_string_len(string_len_s *build)
{
	build->len = FILES;
	build->size = NONE;
	if (!(build->string = calloc(build->len, sizeof(char))))
		rep_error("build->string in init_string_len");
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
 -b db# -r db# [ -f ] [ -s | -t ] [ -c ca-cert]\n");
	else if (strstr(prog, "lcg"))
		fprintf(stderr, " -d domain-name -g gid -n group\
 [ -u user1,user2,...,userN ]\n");
}

void
rep_truncate(const char *what, int max)
{
	fprintf(stderr, "%s truncated. Max allowed is %d\n", what, max - 1);
}

void
init_lcr_data_struct(lcr_t *data)
{
	memset(data, 0, sizeof(lcr_t));
	if (!(data->host = calloc(ONE, DOMAIN)))
		rep_error("host in data");
	if (!(data->domain = calloc(ONE, DOMAIN)))
		rep_error("domain in data");
	if (!(data->user = calloc(ONE, NAME)))
		rep_error("name in data");
	if (!(data->db = calloc(ONE, DB)))
		rep_error("db in data");
	if (!(data->ca = calloc(ONE, DOMAIN)))
		rep_error("ca in data");
	if (!(data->cdb = calloc(ONE, DB)))
		rep_error("cdb in data");
}

void
clean_lcr_data_struct(lcr_t *data)
{
	if (data) {
		if (data->host)
			free(data->host);
		if (data->domain)
			free(data->domain);
		if (data->user)
			free(data->user);
		if (data->db)
			free(data->db);
		if (data->ca)
			free(data->ca);
		if (data->cdb)
			free(data->cdb);
		free(data);
	}
}

void
init_lgc_data_struct(lgc_s *data)
{
	data->domain = '\0';
	data->dc = '\0';
	data->dn = '\0';
	data->name = '\0';
	data->group = 0;
	if (!(data->domain = calloc(ONE, DOMAIN)))
		rep_error("domain in data");
	if (!(data->dc = calloc(ONE, DC)))
		rep_error("dc in data");
	if (!(data->dn = calloc(ONE, DN)))
		rep_error("dn in data");
	if (!(data->name = calloc(ONE, NAME)))
		rep_error("group in data");
	if (!(data->users = calloc(ONE, DN)))
		rep_error("users in data");
}

void
clean_lgc_data(lgc_s *data)
{
	if (data->domain)
		free(data->domain);
	if (data->dc)
		free(data->dc);
	if (data->dn)
		free(data->dn);
	if (data->name)
		free(data->name);
	if (data->users)
		free(data->users);
	if (data)
		free(data);
}
