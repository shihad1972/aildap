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
 *  Shared function defintions for the ldap-col suite of programs
 *
 *  Part of the ldap collection suite of program
 *
 *  (C) Iain M Conochie 2014 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"
#include "base-sha.h"

int
parse_lcdb_command_line(int argc, char *argv[], lcdb_s *data)
{
	int retval = NONE, opt = NONE;

	if (!(data))
		return ONE;
	while ((opt = getopt(argc, argv, "a:d:p:f")) != -1) {
		;
	}
	return retval;
}

int
main (int argc, char *argv[])
{
	char *pass, *phash;

	pass = getPassword("Enter password for admin DN: ");
	phash = get_ldif_pass_hash(pass);
	printf("{SSHA}%s\n", phash);
	free(phash);
	free(pass);
	return NONE;
}
