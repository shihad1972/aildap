/* 
 *
 *  lcdhcp: Collection of ldap utilities
 *  Copyright (C) 2015  Iain M Conochie <iain-AT-thargoid.co.uk> 
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
 *  lcdhcp.c
 *
 *  Main source file for the lcdhcp program
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_GETOPT_H
# define _GNU_SOURCE
# include <getopt.h>
#endif /* HAVE_GETOPT_H */
#include <ailsa.h>
#define WANT_OBCL_TOP	// Expose obcl_top variable
#include <ailsaldap.h>

enum {
	ACT_SERVER = 3,
	ACT_NET = 4,
	ACT_HOST = 5
};


/*
 * These are the objectClasses that we use within this program.
 *
 * For a full list of objectClasses, see the dhcp schema.
 *
 * These are prefixed with dp_
 */
const char *dp_service = "objectClass: dhcpService";
const char *dp_server = "objectClass: dhcpServer";
const char *dp_shr_net = "objectClass: dhcpSharedNetwork";
const char *dp_opt = "objectClass: dhcpOptions";
const char *dp_subnet = "objectClass: dhcpSubnet";
const char *dp_host = "objectClass: dhcpHost";

/*
 * These are some dhcp attribute types that we use within this program.
 *
 * For a full list of attributeTypes, see the dhcp schema.
 *
 * These are prefixed with dh_
 */
const char *dh_mac = "dhcpHWAddress";
const char *dh_stmt = "dhcpStatements";
const char *dh_opt = "dhcpOption";
const char *dh_serv_dn = "dhcpServiceDN";
const char *dh_pri_dn = "dhcpPrimaryDN";
const char *dh_netmask = "dhcpNetMask";

/*
 * Static functions in this file. Add ALL functions within this file here.
 */

static void
fill_dhcp_config(lcdhcp_s *dhcp, AILSA_LIST *list);

static int
parse_lcdhcp_command_line(int argc, char *argv[], lcdhcp_s *data);

static int
check_lcdhcp_command_line(lcdhcp_s *data);

static void
report_lcdhcp_help(void);

static void
report_lcdhcp_error(const char *who, const char *what);

static void
output_dhcp_host_ldif(lcdhcp_s *data);

static void
output_dhcp_server_ldif(lcdhcp_s *data);

static void
output_dhcp_network_ldif(lcdhcp_s *data);

int
main (int argc, char *argv[])
{
	int retval = 0;
	lcdhcp_s *dhcp;
	AILSA_LIST *list;

	dhcp = ailsa_calloc(sizeof(lcdhcp_s), "dhcp in main");
	create_kv_list(&list);
	aildap_parse_config(list, basename(argv[0]));
	fill_dhcp_config(dhcp, list);
	if (argc > 1) {
		if ((retval = parse_lcdhcp_command_line(argc, argv, dhcp)) != 0)
			goto cleanup;
	} else {
		report_lcdhcp_help();
		goto cleanup;
	}
	if (dhcp->action == ACT_VERSION)
		output_version(argv[0]);
	else if (dhcp->action == ACT_HELP)
		report_lcdhcp_help();
	else if (dhcp->action == ACT_HOST)
		output_dhcp_host_ldif(dhcp);
	else if (dhcp->action == ACT_SERVER)
		output_dhcp_server_ldif(dhcp);
	else if (dhcp->action == ACT_NET)
		output_dhcp_network_ldif(dhcp);
	cleanup:
		destroy_kv_list(list);
		my_free(dhcp);
		return retval;
}

static void
fill_dhcp_config(lcdhcp_s *config, AILSA_LIST *list)
{
	config->dn = get_value_from_kv_list(list, "base");
	config->ou = get_value_from_kv_list(list, "ou");
}

static int
parse_lcdhcp_command_line(int argc, char *argv[], lcdhcp_s *data)
{
	int opt;
	int retval = 0;
	const char *optstr = "b:l:r:u:xd:e:g:i:n:k:m:o:htwsv";
#ifdef HAVE_GETOPT_H
	int index;
	struct option l_opts[] = {
		{"basedn",		required_argument,	NULL,	'b'},
		{"domain",		required_argument,	NULL,	'd'},
		{"ethernet",		required_argument,	NULL,	'e'},
		{"filename",		required_argument,	NULL,	'f'},
		{"gateway",		required_argument,	NULL,	'g'},
		{"ip-address",		required_argument,	NULL,	'i'},
		{"netblock",		required_argument,	NULL,	'k'},
		{"boot-file",		required_argument,	NULL,	'l'},
		{"netmask",		required_argument,	NULL,	'm'},
		{"name",		required_argument,	NULL,	'n'},
		{"ou",			required_argument,	NULL,	'o'},
		{"boot-server",		required_argument,	NULL,	'r'},
		{"ddns-update-style",	required_argument,	NULL,	'u'},
		{"disable-booting",	no_argument,		NULL,	'x'},
		{"help",		no_argument,		NULL,	'h'},
		{"host",		no_argument,		NULL,	't'},
		{"network",		no_argument,		NULL,	'w'},
		{"server",		no_argument,		NULL,	's'},
		{"version",		no_argument,		NULL,	'v'},
		{NULL, 0, NULL, 0}
	};
	while ((opt = getopt_long(argc, argv, optstr, l_opts, &index)) != -1)
#else
	while ((opt = getopt(argc, argv, optstr)) != -1)
#endif /* HAVE_GETOPT_H */
	{
		if (opt == 'b') {
			data->dn = optarg;
		} else if (opt == 'l') {
			data->bfile = optarg;
		} else if (opt == 'r') {
			data->bserver = optarg;
		} else if (opt == 'u') {
			data->ddns = optarg;
		} else if (opt == 'x') {
			data->boot = 0;
		} else if (opt == 'd') {
			data->domain = optarg;
		} else if (opt == 'e') {
			data->ether = optarg;
		} else if (opt == 'g') {
			data->gw = optarg;
		} else if (opt == 'i') {
			data->ipaddr = optarg;
		} else if (opt == 'n') {
			data->name = optarg;
		} else if (opt == 'k') {
			data->netb = optarg;
		} else if (opt == 'm') {
			data->netm = optarg;
		} else if (opt == 'o') { // OU not used at present
			data->ou = optarg;
		} else if (opt == 'f') {
			data->filename = optarg;
		} else if (opt == 'h') {
			data->action = ACT_HELP;
		} else if (opt == 't') {
			data->action = ACT_HOST;
		} else if (opt == 'w') {
			data->action = ACT_NET;
		} else if (opt == 's') {
			data->action = ACT_SERVER;
		} else if (opt == 'v') {
			data->action = ACT_VERSION;
		} else {
			report_lcdhcp_help();
			retval = WARG;
		}
	}
	retval = check_lcdhcp_command_line(data);
	return retval;
}

static int
check_lcdhcp_command_line(lcdhcp_s *data)
{
	int retval = 0;
	const char *server = "server";
	const char *network = "network";
	const char *host = "host";
	const char *who, *what;

	if (!(data))		// Sanity check
		return NODATA;
	if (data->action == ACT_HELP || data->action == ACT_VERSION)
		return retval;
	if (data->action == 0) {
		who = "all";
		what = "action";
		goto cleanup;
	}
	if (!(data->dn)) {
		who = "all";
		what = "basedn";
		goto cleanup;
	}
	if (data->action == ACT_SERVER) {
		who = server;
		if (!(data->name)) {
			what = "name";
			goto cleanup;
		}
	} else if (data->action == ACT_NET) {
		who = network;
		if (!(data->domain)) {
			what = "domain";
			goto cleanup;
		} else if (!(data->ipaddr)) {
			what = "name server ip address";
			goto cleanup;
		} else if (!(data->netb)) {
			what = "Network block";
			goto cleanup;
		} else if (!(data->netm)) {
			what = "Netmask";
			goto cleanup;
		}
	} else if (data->action == ACT_HOST) {
		who = host;
		if (!(data->name)) {
			what = "name";
			goto cleanup;
		} else if (!(data->ipaddr)) {
			what = "ip address";
			goto cleanup;
		} else if (!(data->ether)) {
			what = "ether";
			goto cleanup;
		}
	}
	return retval;
	cleanup:
		report_lcdhcp_error(who, what);
		return WARG;
}

static void
report_lcdhcp_help(void)
{
	fprintf(stderr, "\
Usage: lcdhcp ACTION OPTIONS. See man page lcdhcp(1) for details\n");
}

static void
report_lcdhcp_error(const char *who, const char *what)
{
	const char *determiner;
	const char *vowel;
	if (!(who) || !(what))
		return;
	vowel = what;
	if (*vowel == 'a' || *vowel == 'e' || *vowel == 'i' || *vowel == 'o' ||
	    *vowel == 'u')
		determiner = "an";
	else
		determiner = "a";
	if (strncmp(who, "all", 4) == 0)
		fprintf(stderr, "\
Adding any configuration needs %s %s\n", determiner, what);
	else
		fprintf(stderr, "\
Adding a %s configuration needs %s %s\n", who, determiner, what);
}

static void
output_dhcp_host_ldif(lcdhcp_s *data)
{
	FILE *out;
	if (!(data))		// Sanity check
		return;
	if (data->filename) {
		if (!(out =  fopen(data->filename, "w"))) {
			fprintf(stderr, "Cannot open %s for reading!\n", data->filename);
			out = stdout;
		}
	} else {
		out = stdout;
	}
	if (!(data->ou))
		data->ou = "dhcp";
	fprintf(out, "\
# %s, %s, %s\n\
dn: cn=%s,ou=%s,%s\n\
cn: %s\n\
%s\n\
%s\n\
%s\n\
%s: ethernet %s\n\
%s: fixed-address %s\n",
data->name, data->ou, data->dn, data->name, data->ou, data->dn,
data->name, obcl_top, dp_host, dp_opt, dh_mac, data->ether, dh_stmt,
data->ipaddr);
	if (data->domain)
		fprintf(out, "\
%s: domain-name \"%s\"\n", dh_stmt, data->domain);
	if (out != stdout)
		fclose(out);
}

static void
output_dhcp_server_ldif(lcdhcp_s *data)
{
	FILE *out;
	if (!(data))		// Sanity check
		return;
	if (data->filename) {
		if (!(out = fopen(data->filename, "w"))) {
			fprintf(stderr, "Cannot open %s for writing!\n", data->filename);
			out = stdout;
		}
	} else {
		out = stdout;
	}
	if (!(data->ou))
		data->ou = "dhcp";
	fprintf(out, "\
# %s, %s, %s\n\
dn: cn=%s,ou=%s,%s\n\
cn: %s\n\
%s\n\
%s\n\
%s: cn=service,ou=%s,%s\n\n",
data->name, data->ou, data->dn, data->name, data->ou, data->dn,
data->name, obcl_top, dp_server, dh_serv_dn, data->ou, data->dn);
/*
 * Need to do some testing for booting and also ddns style
 */
	fprintf(out, "\
# service, %s, %s\n\
dn: cn=service,ou=%s,%s\n\
cn: service\n\
%s\n\
%s\n\
%s: ou=%s,%s\n\
%s: allow booting\n\
%s: allow bootp\n\
%s: ddns-update-style none\n",
data->ou, data->dn, data->ou, data->dn, obcl_top, dp_service,
dh_pri_dn, data->ou, data->dn, dh_stmt, dh_stmt, dh_stmt);
	if (out != stdout)
		fclose(out);
}

static void
output_dhcp_network_ldif(lcdhcp_s *data)
{
	FILE *out;
	if (!(data))		// Sanity check
		return;
	if (data->filename) {
		if (!(out = fopen(data->filename, "w"))) {
			fprintf(stderr, "Cannot open %s for writing!\n", data->filename);
			out = stdout;
		}
	} else {
		out = stdout;
	}
	if (!(data->ou))
		data->ou = "dhcp";
	fprintf(out, "\
# %s, %s, %s\n\
dn: cn=%s,cn=service,ou=%s,%s\n\
cn: %s\n\
%s\n\
%s\n\
%s\n\
%s: domain-name-servers %s\n\
%s: domain-search \"%s\"\n", data->domain, data->ou, data->dn, data->domain,
data->ou, data->dn, data->domain, obcl_top, dp_shr_net, dp_opt, dh_opt,
data->ipaddr, dh_opt, data->domain);
	if (data->gw)
		fprintf(out, "\
%s: routers %s\n\n", dh_opt, data->gw);
	else
		fprintf(out, "\n");
	fprintf(out, "\
# %s, %s, %s, %s\n\
dn: cn=%s,cn=%s,cn=service,ou=%s,%s\n\
cn: %s\n\
%s\n\
%s\n\
%s: %s\n\
%s: authoratative\n\
%s: next-server %s\n\
%s: filename \"pxelinux.0\"\n", data->netb, data->domain, data->ou, data->dn,
data->netb, data->domain, data->ou, data->dn, data->netb, obcl_top, dp_subnet,
dh_netmask, data->netm, dh_stmt, dh_stmt, data->ipaddr, dh_stmt);
	if (out != stdout)
		fclose(out);
}

