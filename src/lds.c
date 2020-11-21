/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2013-2014  Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  lds.c:
 * 
 *  Test searching in ldap directory
 * 
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif // HAVE_GETOPT_H
#include <errno.h>
#include <error.h>
#include <ldap.h>
#include <ailsaldap.h>

int
main(int argc, char *argv[])
{
        int retval = 0;
        int count;
        int proto = LDAP_VERSION3;
        char *dn = NULL;
        const char *user = "uid=cmdb,ou=people,dc=shihad,dc=org";
        const char *host = "ldap://kerberos01.shihad.org:389";
        const char *pass = "aiGeeYw5S9z3mnXn8QPM";
        const char *base_dn = "ou=people,dc=shihad,dc=org";
        const char *filter = "(sn=Conochie)";
        LDAP *shihad = NULL;
        LDAPMessage *res = NULL;
        LDAPMessage *e = NULL;

        if ((retval = ldap_initialize(&shihad, host)) != LDAP_SUCCESS) {
                fprintf(stderr, "Connect failed with %s\n", ldap_err2string(retval));
                fprintf(stderr, "ldap uri was %s\n", host);
        }
        if ((retval = ldap_set_option(shihad, LDAP_OPT_PROTOCOL_VERSION, &proto)) != LDAP_SUCCESS) {
                fprintf(stderr, "Cannot set protocol version to v3\n");
		if (shihad)
			ldap_unbind(shihad);
		exit(1);
        }
        if ((retval = ldap_simple_bind_s(shihad, user, pass)) != LDAP_SUCCESS) {
                fprintf(stderr, "Bind failed with %s\n", ldap_err2string(retval));
		if (shihad)
			ldap_unbind(shihad);
                exit(2);
        }
        if ((retval = ldap_search_s(shihad, base_dn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, &res)) != LDAP_SUCCESS) {
                fprintf(stderr, "Search failed with %s\n", ldap_err2string(retval));
                if (shihad)
                        ldap_unbind(shihad);
                exit(3);
        }
        printf("We have %d entries\n", ldap_count_entries(shihad, res));
        for (e = ldap_first_entry(shihad, res); e != NULL; e = ldap_next_entry(shihad, e)) {
                dn = ldap_get_dn(shihad, e);
                printf("dn: %s\n", dn);
                free(dn);
                dn = NULL;
        }
        ldap_msgfree(res);
        ldap_msgfree(e);
        ldap_unbind(shihad);
        return retval;
}