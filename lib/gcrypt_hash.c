
/*
 *
 *  aildap: collection of ldap utilities
 *  Copyright (C) 2024  Iain M Conochie <iain-AT-ailsatech-DOT-net>
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
 *  gcrypt_hash.c
 *
 *  Contains the hashing functions for generating passwords for slapd
 *  and also various other functions. Part of the ailsaldap library
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <gcrypt.h>

const char *
ailsa_init_grcypt(const char *version)
{
	const char *v;
	v =  gcry_check_version(version);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	return v;
}

int
ailsa_get_hash_method(const char *hash)
{
        int retval;

        if (strcmp(hash, "sha1"))
                retval = GCRY_MD_SHA1;
        else if (strcmp(hash, "sha224"))
                retval = GCRY_MD_SHA224;
        else if (strcmp(hash, "sha256"))
                retval = GCRY_MD_SHA256;
        else if (strcmp(hash, "sha512"))
                retval = GCRY_MD_SHA512;
        else
                retval = -1;
        return retval;
}
