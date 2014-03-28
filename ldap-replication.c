#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"

void
check_snprintf(char *target, int max, const char *string, const char *what)
{
	int retval;

	retval = snprintf(target, max, "%s", string);
	if (retval > max)
		rep_truncate(what, max);
	else if (retval < 0)
		fprintf(stderr, "Output error for %s\n", what);
}

int
parse_lcr_command_line(int argc, char *argv[], lcr_t *data)
{
	int retval = NONE, opt = NONE;

	if (!(data))
		return NODATA;
	while ((opt = getopt(argc, argv, "b:c:d:h:r:u:fts")) != -1) {
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
		else if (opt == 'u')
			check_snprintf(data->user, DOMAIN, optarg, "data->user");
		else if (opt == 'f')
			data->file = 1;
		else if (opt == 't')
			data->tls = 1;
		else if (opt == 's')
			data->ssl = 1;
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
	if (((data->tls > 0) || (data->ssl > 0)) && (strlen(data->ca) == 0))
		fprintf(stderr, "No certificate provided. Adding tls_reqcert=never\n\n");
	return retval;
}

char *
get_ldif_domain(char *dom)
{
	char *ldom, *tmp, *save, *empty = '\0', *buff, *domain;
	const char *delim = ".";
	int c = NONE;
	size_t len = NONE;

	if (!(buff = malloc(DOMAIN)))
		rep_error("buff in get_ldif_domain");
	len = strlen(dom);
	if (!(domain = calloc((len + 1), sizeof(char))))
		rep_error("domain in get_ldif_domain");
	strncpy(domain, dom, len);
	tmp = domain;
	while ((tmp = strchr(tmp, '.'))) {
		tmp++;
		c++;
	}
	len = strlen(dom) + (size_t)(c * 3);
	if (len >= DOMAIN) {
		if(!(ldom = malloc(DN))) {
			rep_error("ldom in get_ldif_domain");
		}
	} else {
		if (!(ldom = malloc(DOMAIN))) {
			rep_error("ldom in get_ldif_domain");
		}
	}
	tmp = strtok_r(domain, delim, &save);
	sprintf(ldom, "dc=%s", tmp);
	while ((tmp = strtok_r(empty, delim, &save))) {
		sprintf(buff, ",dc=%s", tmp);
		strcat(ldom, buff);
	}
	free(buff);
	free(domain);
	return ldom;
}

int
print_provider(lcr_t *data)
{
	FILE *provider;
	char *dom;
	const char *file = "provider.ldif";

	if (data->file > 0) {
		if (!(provider = fopen(file, "w")))
			return FILE_O_FAIL;
	} else {
		provider = stdout;
	}
	dom = get_ldif_domain(data->domain);
	fprintf(provider, "\
#Load the accesslog module\n\
dn: cn=module{0},cn=config\n\
changeType: modify\n\
add: olcModuleLoad\n\
olcModuleLoad: accesslog\n\
olcModuleLoad: syncprov\n\
\n\
# Accesslog database definition\n\
dn: olcDatabase=hdb,cn=config\n\
objectClass: olcDatabaseConfig\n\
objectClass: olcHdbConfig\n\
olcDatabase: hdb\n\
olcDbDirectory: /var/lib/slapd/accesslog\n\
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
data->user, dom, data->cdb, data->db, data->db);
	if (data->file > 1)
		fclose(provider);
	return NONE;
}

int
main (int argc, char *argv[])
{
	int retval = NONE;
	lcr_t *data = '\0';
	if (!(data = malloc(sizeof(lcr_t))))
		rep_error("data");
	init_lcr_data_struct(data);
	if ((retval = parse_lcr_command_line(argc, argv, data)) > 0) {
		clean_lcr_data_struct(data);
		return retval;
	}
	print_provider(data);
	clean_lcr_data_struct(data);
	return retval;
}