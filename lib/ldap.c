/*
 *
 *  aildap: collection of ldap utilities
 *  Copyright (C) 2023  Iain M Conochie <iain-AT-ailsatech-DOT-net>
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
 *  ldap.c
 *
 *  LDAP function defintions for the ailsa ldap library
 *
 *  Part of the ldap collection suite of program
 *
 */

#include <config.h>
#include <stdio.h>
#include <syslog.h>
#include <ldap.h>
#include <ailsa.h>
#include <ailsaldap.h>

void
ailsa_ldap_init(LDAP **ailsa, const char *url)
{
        int retval, proto = LDAP_VERSION3;

        if ((retval = ldap_initialize(ailsa, url)) != LDAP_SUCCESS) {
                ailsa_syslog(LOG_DAEMON, "Cannot initialise LDAP library in ailsa_ldap_init");
                exit(MALLOC);
        }
        if ((retval = ldap_set_option(*ailsa, LDAP_OPT_PROTOCOL_VERSION, &proto)) != LDAP_SUCCESS) {
                ailsa_syslog(LOG_DAEMON, "Cannot set protocol version to v3 in ailsa_ldap_init");
		exit(ONE);
        }
}
