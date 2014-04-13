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
# include "ldap-col.h"

char *
getPassword(const char *message);

void
rep_err(const char *error);

void
split_name(inp_data_s *data);

void
output_ldif(inp_data_s *data);

char *
get_ldif_pass_hash(char *pass);

int
hex_conv(const char *pass, guchar *out);

#endif /* HAVE_BASE_H */
