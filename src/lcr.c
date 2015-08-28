/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2014-2015 Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  lcr.c
 *
 *  Main file for lcr - ldpa create replication
 *
 *  Part of the ldap collection suite of program
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include "ldap-col.h"
#include "base-sha.h"

int
parse_lcr_command_line(int argc, char *argv[], lcr_t *data)
{
	const char arguments[] = "b:c:d:h:p:r:u:ftsCMP";
	int retval = NONE, opt = NONE;

	if (!(data))
		return NODATA;
	while ((opt = getopt(argc, argv, arguments)) != -1) {
		if (opt == 'b')
			check_snprintf(data->db, DB, optarg, "data->db");
		else if (opt == 'c')
			check_snprintf(data->ca, DOMAIN, optarg, "data->ca");
		else if (opt == 'd')
			check_snprintf(data->domain, DOMAIN, optarg, "data->domain");
		else if (opt == 'h')
			check_snprintf(data->host, DOMAIN, optarg, "data->host");
		else if (opt == 'r')
			check_snprintf(data->cdb, DB, optarg, "data->cbd");
		else if (opt == 'p')
			check_snprintf(data->pdb, DB, optarg, "data->pdb");
		else if (opt == 'u')
			check_snprintf(data->user, DOMAIN, optarg, "data->user");
		else if (opt == 'f')
			data->file = 1;
		else if (opt == 't')
			data->tls = 1;
		else if (opt == 's')
			data->ssl = 1;
		else if (opt == 'C')
			data->cons = 1;
		else if (opt == 'M')
			data->mod = 1;
		else if (opt == 'P')
			data->prov = 1;
		else {
			rep_usage(argv[0]);
			return WARG;
		}
	}
	if ((strlen(data->db) == 0) || (strlen(data->domain) == 0) ||
	 (strlen(data->host) == 0) || (strlen(data->user) == 0) ||
	 (strlen(data->cdb) == 0)) {
		rep_usage(argv[0]);
		return WARG;
	}
	if ((data->tls > 0) && (data->ssl > 0)) {
		fprintf(stderr, "Only one of -t or -s is allowed\n");
		rep_usage(argv[0]);
		return WARG;
	}
	if ((data->prov > 0) && (data->cons > 0)) {
		fprintf(stderr, "Only one of -C or -P is allowed\n");
		rep_usage(argv[0]);
		return WARG;
	}
	if (((data->tls > 0) || (data->ssl > 0)) && (strlen(data->ca) == 0))
		fprintf(stderr, "No certificate provided. Adding tls_reqcert=never\n\n");
	return retval;
}

int
print_provider(lcr_t *data)
{
	FILE *provider;
	char *dom = '\0';
	const char *file = "provider.ldif";

	if (data->file > 0) {
		if (!(provider = fopen(file, "w")))
			return FILE_O_FAIL;
	} else {
		provider = stdout;
	}
	dom = get_ldif_domain(data->domain);
	if (data->mod == 0)
		fprintf(provider, "\
#Load the accesslog module\n\
dn: cn=module{0},cn=config\n\
changeType: modify\n\
add: olcModuleLoad\n\
olcModuleLoad: accesslog\n\
olcModuleLoad: syncprov\n\
\n");
	fprintf(provider, "\
# Accesslog database definition\n\
dn: olcDatabase=hdb,cn=config\n\
objectClass: olcDatabaseConfig\n\
objectClass: olcHdbConfig\n\
olcDatabase: hdb\n\
olcDbDirectory: /var/lib/slapd/%s/accesslog\n\
olcSuffix: cn=accesslog\n\
olcRootDN: cn=%s,%s\n\
olcDbIndex: default eq\n\
olcDbIndex: entryCSN,objectClass,reqEnd,reqResult,reqStart\n\
\n\
# Accesslog DB syncprov\n\
dn: olcOverlay=syncprov,olcDatabase={%s}hdb,cn=config\n\
changeType: add\n\
objectClass: olcOverlayConfig\n\
objectClass: olcSyncProvConfig\n\
olcOverlay: syncprov\n\
olcSpNoPresent: TRUE\n\
olcSpReloadHint: TRUE\n\
\n\
# syncrepl Provider for primary db\n\
dn: olcOverlay=syncprov,olcDatabase={%s}hdb,cn=config\n\
changetype: add\n\
objectClass: olcOverlayConfig\n\
objectClass: olcSyncProvConfig\n\
olcOverlay: syncprov\n\
olcSpNoPresent: TRUE\n\
\n\
# accesslog overlay definitions for primary db\n\
dn: olcOverlay=accesslog,olcDatabase={%s}hdb,cn=config\n\
objectClass: olcOverlayConfig\n\
objectClass: olcAccessLogConfig\n\
olcOverlay: accesslog\n\
olcAccessLogDB: cn=accesslog\n\
olcAccessLogOps: writes\n\
olcAccessLogSuccess: TRUE\n\
# scan the accesslog DB every day, and purge entries older than 7 days\n\
olcAccessLogPurge: 07+00:00 01+00:00\n\
",
data->domain, data->user, dom, data->pdb, data->db, data->db);
	if (data->file > 1)
		fclose(provider);
	if (dom)
		free(dom);
	return NONE;
}

int
print_consumer(lcr_t *data)
{
	FILE *consumer;
	char *dom, *phash = '\0';
	const char *file = "consumer.ldif";

	if (data->file > 0) {
		if (!(consumer = fopen(file, "w")))
			return FILE_O_FAIL;
	} else {
		consumer = stdout;
		printf("\n");
	}
	dom = get_ldif_domain(data->domain);
	/* This is not actually used. When I do, I will need a fallback */
#ifdef HAVE_OPENSSL
	phash = get_ldif_pass_hash(data->pass);
#endif /* HAVE_OPENSSL */
	if (data->mod == 0)
		fprintf(consumer, "\
#Load the syncprov module.\n\
dn: cn=module{0},cn=config\n\
changetype: modify\n\
add: olcModuleLoad\n\
olcModuleLoad: syncprov\n\
\n");
	fprintf(consumer, "\
# syncrepl specific indices\n\
dn: olcDatabase={%s}hdb,cn=config\n\
changetype: modify\n\
add: olcDbIndex\n\
olcDbIndex: entryUUID eq\n\
-\n\
add: olcSyncRepl\n", data->cdb); 
	if (data->ssl == 0)
		fprintf(consumer, "\
olcSyncRepl: rid=0 provider=ldap://%s bindmethod=simple binddn=\"cn=%s,%s\" \
credentials=%s searchbase=\"%s\" logbase=\"cn=accesslog\" \
logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" \
schemachecking=on type=refreshAndPersist retry=\"60 +\" syncdata=accesslog\n",
data->host, data->user, dom, data->pass, dom);
	free(phash);
	free(dom);

/*
olcSyncRepl: rid=0 provider=ldap://%s bindmethod=simple binddn=\"cn=%s,%s\" credentials=%s searchbase=\"%s\" logbase=\"cn=accesslog\" logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" schemachecking=on type=refreshAndPersist retry=\"60 +\" syncdata=accesslog\n\
-\n\
add: olcUpdateRef\n\
olcUpdateRef: ldap://%s\n", , data->host, data->user, dom, 
*/
	return 0;
}

int
main (int argc, char *argv[])
{
	int retval = NONE;
	lcr_t *data = '\0';
	if (!(data = malloc(sizeof(lcr_t))))
		error(MALLOC, errno, "data in main");
	init_lcr_data_struct(data);
	if ((retval = parse_lcr_command_line(argc, argv, data)) > 0) {
		clean_lcr_data_struct(data);
		return retval;
	}
	if (data->prov == 0)
		data->pass = getPassword("Enter admin DN password: ");
	if (data->cons == 0)
		print_provider(data);
	if (data->prov == 0)
		print_consumer(data);
	if (data->pass)
		free(data->pass);
	clean_lcr_data_struct(data);
	return retval;
}
