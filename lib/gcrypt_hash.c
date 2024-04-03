
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <gcrypt.h>
#include <ailsa.h>
#include <ailsaldap.h>

const char *
ailsa_init_gcrypt(const char *version)
{
	const char *v;
        if (!(v = gcry_check_version(version))) {
                ailsa_syslog(LOG_DAEMON, "libgcrypt too old: need version %s, we have %s", version, v);
                return NULL;
        }
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	return v;
}

const char *
ailsa_init_sec_gcrypt(const char *version, unsigned int bytes)
{
        const char *v;
        if (!(v = gcry_check_version(version))) {
                ailsa_syslog(LOG_DAEMON, "libgcrypt too old: need version %s, we have %s", version, v);
                return NULL;
        }
        gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
        gcry_control (GCRYCTL_INIT_SECMEM, bytes, 0);
        gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
        return v;
}

int
ailsa_get_hash_method(const char *hash)
{
        int retval;

        if (strcmp(hash, "sha1") == 0)
                retval = GCRY_MD_SHA1;
        else if (strcmp(hash, "sha224") == 0)
                retval = GCRY_MD_SHA224;
        else if (strcmp(hash, "sha256") == 0)
                retval = GCRY_MD_SHA256;
        else if (strcmp(hash, "sha512") == 0)
                retval = GCRY_MD_SHA512;
        else
                retval = -1;
        return retval;
}

size_t
ailsa_get_hash_len(const char *hash)
{
        size_t len;

        if (strcmp(hash, "sha1") == 0)
                len = 20;
        else if (strcmp(hash, "sha224") == 0)
                len = 28;
        else if (strcmp(hash, "sha256") == 0)
                len = 32;
        else if (strcmp(hash, "sha512") == 0)
                len = 64;
        else
                len = 0;
        return len;
}

unsigned char *
ailsa_hash_string(const char *string, const char *method)
{
        int hash;

        if ((hash = ailsa_get_hash_method(method)) < 0) {
                ailsa_syslog(LOG_DAEMON, "wrong hash method provided: %s", method);
                return NULL;
        }
        if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
                ailsa_syslog(LOG_DAEMON, "libgcrypt must be initialised before calling this function");
                return NULL;
        }
        unsigned char *output = ailsa_calloc(HASH_LEN, "output in ailsa_hash_string");
        gcry_md_hash_buffer(hash, output, string, strlen(string));
        return output;
}

unsigned char *
ailsa_get_pass_hash(char *pass, const char *type, size_t len)
{
        if (!(pass) || !(type))
                return NULL;
        if (strlen(pass) > len)
                return NULL;
	int rd = open("/dev/urandom", O_RDONLY), i;
	char *npass = NULL, salt[7], *p;
        unsigned char *out, *hpass;
        size_t slen;

        memset(salt, 0, 7);
	if ((read(rd, &salt, 6)) != 6) {
		close(rd);
		rep_err("Could not read enough random data");
	}
        close(rd);
        npass = ailsa_calloc(len + 7, "npass in ailsa_get_pass_hash");
        p = stpcpy(npass, pass);
        for (i = 0; i < 6; i++)
                *(p + i) = salt[i];
        p = stpcpy(p, salt);
        if (!(out = ailsa_hash_string(npass, type))) {
                ailsa_syslog(LOG_DAEMON, "ailsa_hash_string failed in ailsa_get_pass_hash");
                my_free(npass);
                return NULL;
        }
        if ((slen = ailsa_get_hash_len(type)) == 0) {
                ailsa_syslog(LOG_DAEMON, "Unknown hash algorithm %s", type);
                my_free(npass);
                return NULL;
        }
        if (slen == HASH_LEN)
                p = realloc(out, HASH_LEN + 7);
        p = (char *)out + slen;
        for (i = 0; i < 6; i++)
                *(p + i) = salt[i];
        hpass = ailsa_b64_encode(out, slen + 6);
        return hpass;
}
