#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	fprintf(stderr, "Usage: %s -d domain -h host -u user\
 -b db# -r db# [ -f ] [ -s | -t ] [ -c ca-cert]\n", prog);
}

void
rep_truncate(const char *what, int max)
{
	fprintf(stderr, "%s truncated. Max allowed is %d\n", what, max - 1);
}

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

void
init_data_struct(lrc_t *data)
{
	memset(data, 0, sizeof(lrc_t));
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
clean_data_struct(lrc_t *data)
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

int
parse_command_line(int argc, char *argv[], lrc_t *data)
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
print_provider(lrc_t *data)
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
	lrc_t *data = '\0';
	if (!(data = malloc(sizeof(lrc_t))))
		rep_error("data");
	init_data_struct(data);
	if ((retval = parse_command_line(argc, argv, data)) > 0) {
		clean_data_struct(data);
		return retval;
	}
	print_provider(data);
	clean_data_struct(data);
	return retval;
}