#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ldap.h>

enum {
	NONE = 0,
        ONE,
        INSERT,
        REMOVE,
        MALLOC,
        WARG,
        NODOM,
	NOUSER,
	NOHOST,
	CONFAIL,
	BINDFAIL,
	FAIL,
        DC = 64,
        DNL = 67,
	USER = 70,
        DOMAIN = 256,
        DN = 512

};

typedef struct cont_s {
        char *domain, *dc, *dn, *host, *user;
        short int action, sudo;
} cont_s;

void
report_error(const char *error)
{
        fprintf(stderr, "Cannot allocate memory for %s\n", error);
        exit(MALLOC);
}

void
init_data_struct(cont_s *data)
{
        data->domain = '\0';
        data->dc = '\0';
        data->dn = '\0';
        data->host = '\0';
        data->user = '\0';
        data->action = 0;
        if (!(data->domain = calloc(ONE, DOMAIN)))
                report_error("domain in data");
        if (!(data->dc = calloc(ONE, DC)))
                report_error("dc in data");
        if (!(data->dn = calloc(ONE, DN)))
                report_error("dn in data");
	if (!(data->host = calloc(ONE, DOMAIN)))
		report_error("host in data");
	if (!(data->user = calloc(ONE, DC)))
		report_error("user in data");
}

void
clean_data(cont_s *data)
{
	if (data) {
		if (data->domain)
			free(data->domain);
		if (data->dc)
			free(data->dc);
		if (data->dn)
			free(data->dn);
		if (data->host)
			free(data->host);
		if (data->user)
			free(data->user);
		free(data);
	}
}

int
parse_command_line(int argc, char *argv[], cont_s *data)
{
	int retval = NONE, opt = NONE;

	while ((opt = getopt(argc, argv, "d:h:u:")) != -1) {
		if (opt == 'd') {
			if ((retval = snprintf(data->domain, DOMAIN, "%s", optarg)) > DOMAIN) {
				fprintf(stderr, "Domain truncated!\n");
				fprintf(stderr, "Max 255 characters in a domain name\n");
			}
			retval = NONE;
		} else if (opt == 'u') {
			if ((retval = snprintf(data->user, DC, "uid=%s", optarg)) > DC) {
				fprintf(stderr, "User truncated!\n");
				fprintf(stderr, "Max 63 characters in a user name\n");
			}
			retval = NONE;
		} else if (opt == 'h') {
			if ((retval = snprintf(data->host, DOMAIN, "ldap://%s:%d", optarg, LDAP_PORT)) > DOMAIN) {
				fprintf(stderr, "Host truncated!\n");
				fprintf(stderr, "Max 240 characters in a host name\n");
			}
			retval = NONE;
		} else {
			fprintf(stderr, "Usage: %s -d domain -u user\n", argv[0]);
			return WARG;
		}
	}
	if (strlen(data->domain) == NONE) {
		fprintf(stderr, "No domain specified\n");
		retval = NODOM;
	} else if (strlen(data->user) == NONE) {
		fprintf(stderr, "No user specified\n");
		retval = NOUSER;
	} else if (strlen(data->host) == NONE) {
		fprintf(stderr, "No host specified\n");
		retval = NOHOST;
	}
	return retval;
}

int
main (int argc, char *argv[])
{
	int retval = NONE, proto = LDAP_VERSION3;
/*	const char user[] = "test@shihad.org", pass[] = "***"; */
	LDAP *shihad = '\0';
	cont_s *data = '\0';

        if (!(data = calloc(ONE, sizeof(cont_s))))
                report_error("data");
	init_data_struct(data);
	if ((retval = parse_command_line(argc, argv, data)) != 0) {
		if (data)
			clean_data(data);
		exit (retval);
	}
	if ((retval = ldap_initialize(&shihad, data->host)) != 0) {
		fprintf(stderr, "Connect failed with %s\n", ldap_err2string(retval));
		fprintf(stderr, "ldap uri was %s\n", data->host);
		if (data)
			clean_data(data);
		exit (CONFAIL);
	}
	if ((retval = ldap_set_option(shihad, LDAP_OPT_PROTOCOL_VERSION, &proto)) != 0) {
		fprintf(stderr, "Cannot set protocol version to v3\n");
		if (shihad)
			ldap_unbind(shihad);
		if (data)
			clean_data(data);
		exit (FAIL);
	}
	if ((retval = ldap_simple_bind_s(shihad, NULL, NULL)) != NONE) {
		fprintf(stderr, "Bind failed with %s\n", ldap_err2string(retval));
		if (shihad)
			ldap_unbind(shihad);
		if (data)
			clean_data(data);
		exit (BINDFAIL);
	}
	
	if (shihad)
		ldap_unbind(shihad);
	if (data)
		clean_data(data);
	return retval;
}
