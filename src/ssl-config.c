/*
 * ssl-config.c (C) 2013 Iain M Conochie
 * 
 * Program to create the configuration for slapd
 * to have SSL and TLS connections. This is based
 * on the public / private key pair and also the CA certificate.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct cert_s {
	char *domain, *ca;
	short int action;
} cert_s;

enum {
	DOMLONG = 1,
	CALONG = 2,
	ARG_UNKNOWN = 3,
	NODOM = 4,
	MALLOC = 5
};

enum {
	NONE = 0,
	INSERT = 1,
	REMOVE = 2,
	CANAME = 64,
	DOMAIN = 256
};

int
parse_command_line(int argc, char *argv[], cert_s *data)
{
	int retval = NONE, opt = NONE;
	size_t alen = NONE, dlen = NONE;

	while ((opt = getopt(argc, argv, "a:d:ir")) != -1) {
		if (opt == 'd') {
			if ((dlen = strlen(optarg)) > (DOMAIN - 1)) {
				fprintf(stderr, "\
Domain name too large ( > 255)\n");
				retval = DOMLONG;
			}
			snprintf(data->domain, DOMAIN, "%s", optarg);
		} else if (opt == 'a') {
			if ((alen = strlen(optarg)) > (CANAME - 1)) {
				fprintf(stderr, "\
CA cert name too large ( > 63 )\n");
				retval = CALONG;
			}
			snprintf(data->ca, CANAME, "%s", optarg);
		} else if (opt == 'i') {
			data->action = INSERT;
		} else if (opt == 'r') {
			data->action = REMOVE;
		} else {
			fprintf(stderr, "Usage: %s -a CA-cert -d domain [ -i | r ]\n",
				argv[0]);
			retval = ARG_UNKNOWN;
		}
	}
	if (retval != NONE)
		return (retval);
	if ((dlen == NONE) && (data->action == INSERT)) {
		fprintf(stderr, "No domain provided\n");
		fprintf(stderr, "Usage: %s -a CA-cert -d domain [ -i | r ]\n",
			argv[0]);
		retval = NODOM;
	}
	if ((alen == NONE) && (data->action == REMOVE)) {
		fprintf(stderr, "No CA Certificate name provided\n");
		fprintf(stderr, "Assuming self certified certificate\n--\n\n");
	}
	return retval;
}

void
report_error(const char *name)
{
	printf("Var %s malloc() failed\n", name);
	exit (MALLOC);
}

void
init_data_struct(cert_s *data)
{
	data->domain = '\0';
	data->ca = '\0';
	data->action = 0;
	if (!(data->domain = malloc(DOMAIN)))
		report_error("data->domain");
	if (!(data->ca = malloc(CANAME)))
		report_error("data->ca");
}

void
clean_data(cert_s *data)
{
	if (data->domain)
		free(data->domain);
	if (data->ca)
		free(data->ca);
	if (data)
		free(data);
}

void
output_insert_ssl(cert_s *data)
{
	if (strlen(data->ca) != 0)
		printf("\
dn: cn=config\n\
changeType: modify\n\
add: olcTLSCACertificateFile\n\
olcTLSCACertificateFile: /etc/ssl/certs/%s.pem\n\
-\n\
add: olcTLSCertificateFile\n\
olcTLSCertificateFile: /etc/ldap/ssl.crt/%s.crt\n\
-\n\
add: olcTLSCertificateKeyFile\n\
olcTLSCertificateKeyFile: /etc/ldap/ssl.key/%s.pem\n\
-\n\
add: olcTLSCRLCheck\n\
olcTLSCRLCheck: none\n\
-\n\
add: olcTLSVerifyClient\n\
olcTLSVerifyClient: never\n\n\
", data->ca, data->domain, data->domain);
	else
		printf("\
dn: cn=config\n\
changeType: modify\n\
add: olcTLSCertificateFile\n\
olcTLSCertificateFile: /etc/ldap/ssl.crt/%s.crt\n\
-\n\
add: olcTLSCertificateKeyFile\n\
olcTLSCertificateKeyFile: /etc/ldap/ssl.key/%s.pem\n\
-\n\
add: olcTLSCRLCheck\n\
olcTLSCRLCheck: none\n\
-\n\
add: olcTLSVerifyClient\n\
olcTLSVerifyClient: never\n\n\
", data->domain, data->domain);

}

void
output_remove_ssl(cert_s *data)
{
	if (strlen(data->ca) != 0)
		printf("\
dn: cn=config\n\
changeType: modify\n\
delete: olcTLSCACertificateFile\n\
-\n\
delete: olcTLSCertificateFile\n\
-\n\
delete: olcTLSCertificateKeyFile\n\
-\n\
delete: olcTLSCRLCheck\n\
-\n\
delete: olcTLSVerifyClient\n\n\
");
	else
		printf("\
dn: cn=config\n\
changeType: modify\n\
delete: olcTLSCertificateFile\n\
-\n\
delete: olcTLSCertificateKeyFile\n\
-\n\
delete: olcTLSCRLCheck\n\
-\n\
delete: olcTLSVerifyClient\n\n\
");
}

int
main (int argc, char *argv[])
{
	int retval = NONE;
	cert_s *data = NONE;

	if (!(data = malloc(sizeof(cert_s))))
		report_error("data");
	init_data_struct(data);
	if ((retval = parse_command_line(argc, argv, data)) != NONE) {
		clean_data(data);
		exit (retval);
	}
	if (data->action == INSERT)
		output_insert_ssl(data);
	else if (data->action == REMOVE)
		output_remove_ssl(data);
	else {
		fprintf(stderr, "No action specified\n");
		fprintf(stderr, "Usage: %s -a CA-cert -d domain [ -i | r ]\n",
			argv[0]);
	}
	return (retval);
}