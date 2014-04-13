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
#include "ldap-col.h"

int
parse_command_line(int argc, char *argv[], cert_s *data)
{
	int retval = NONE, opt = NONE;
	size_t alen = NONE, dlen = NONE;

	data->action = INSERT;
	while ((opt = getopt(argc, argv, "a:h:ir")) != -1) {
		if (opt == 'h') {
			if ((dlen = strlen(optarg)) > (DOMAIN - 1)) {
				fprintf(stderr, "\
Host name too large ( > 255)\n");
				retval = DOMLONG;
			}
			snprintf(data->hostname, DOMAIN, "%s", optarg);
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
			rep_usage(argv[0]);
			retval = WARG;
		}
	}
	if (retval != NONE)
		return (retval);
	if ((dlen == NONE) && (data->action == INSERT)) {
		fprintf(stderr, "No hostname provided\n");
		rep_usage(argv[0]);
		retval = NODOM;
	}
	if ((alen == NONE) && (data->action == REMOVE)) {
		fprintf(stderr, "No CA Certificate name provided\n");
		fprintf(stderr, "Assuming self certified certificate\n--\n\n");
	}
	return retval;
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
", data->ca, data->hostname, data->hostname);
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
", data->hostname, data->hostname);

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
		rep_error("data");
	init_lcs_data_struct(data);
	if ((retval = parse_command_line(argc, argv, data)) != NONE) {
		clean_lcs_data(data);
		exit (retval);
	}
	if (data->action == REMOVE)
		output_remove_ssl(data);
	else {
		output_insert_ssl(data);
	}
	clean_lcs_data(data);
	return (retval);
}
