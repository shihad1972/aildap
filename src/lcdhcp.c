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
#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_GETOPT_H
# define _GNU_SOURCE
# include <getopt.h>
#endif /* HAVE_GETOPT_H */
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
const char *dp_ser = "objectClass: dhcpService";
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
const char *dh_stmt = "dhcpStaements";
const char *dh_opt = "dhcpOption";

/*
 * Static functions in this file. Add ALL functions within this file here.
 */
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

int
main (int argc, char *argv[])
{
	int retval = 0;
	lcdhcp_s *dhcp;

	if (argc == 1) {
		report_lcdhcp_help();
		return retval;
	}
	if (!(dhcp = malloc(sizeof(lcdhcp_s))))
		error(MALLOC, errno, "dhcp in main");
	init_lcdhcp_data_struct(dhcp);
	if ((retval = parse_lcdhcp_command_line(argc, argv, dhcp)) != 0)
		goto cleanup;
	if (dhcp->basedn) {
		if (!(dhcp->dn = get_ldif_format(dhcp->basedn, "dc", ".")))
			rep_err("Cannot convert basedn\n");
	}
	if (dhcp->action == ACT_VERSION)
		output_version(argv[0]);
	else if (dhcp->action == ACT_HELP)
		report_lcdhcp_help();
	else if (dhcp->action == ACT_HOST)
		output_dhcp_host_ldif(dhcp);
	cleanup:
		clean_lcdhcp_data(dhcp);
		return retval;
}

static int
parse_lcdhcp_command_line(int argc, char *argv[], lcdhcp_s *data)
{
	int opt;
	int retval = 0;
	const char *optstr = "b:l:r:c:u:xd:e:g:i:a:k:m:o:htnsv";
#ifdef HAVE_GETOPT_H
	int index;
	struct option l_opts[] = {
		{"basedn",		required_argument,	NULL,	'b'},
		{"boot-file",		required_argument,	NULL,	'l'},
		{"boot-server",		required_argument,	NULL,	'r'},
		{"container",		required_argument,	NULL,	'c'},
		{"ddns-update-style",	required_argument,	NULL,	'u'},
		{"disable-booting",	no_argument,		NULL,	'x'},
		{"domain",		required_argument,	NULL,	'd'},
		{"ethernet",		required_argument,	NULL,	'e'},
		{"gateway",		required_argument,	NULL,	'g'},
		{"ip-address",		required_argument,	NULL,	'i'},
		{"name",		required_argument,	NULL,	'a'},
		{"netblock",		required_argument,	NULL,	'k'},
		{"netmask",		required_argument,	NULL,	'm'},
		{"ou",			required_argument,	NULL,	'o'},
		{"filename",		required_argument,	NULL,	'f'},
		{"help",		no_argument,		NULL,	'h'},
		{"host",		no_argument,		NULL,	't'},
		{"network",		no_argument,		NULL,	'n'},
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
			if (!(data->basedn = strndup(optarg, DOMAIN - 1)))
				error(MALLOC, errno, "data->basedn");
		} else if (opt == 'l') {
			if (!(data->bfile = strndup(optarg, FILES - 1)))
				error(MALLOC, errno, "data->bfile");
		} else if (opt == 'r') {
			if (!(data->bserver = strndup(optarg, INET6_ADDRSTRLEN - 1)))
				error(MALLOC, errno, "data->bserver");
		} else if (opt == 'c') {
			if (!(data->cont = strndup(optarg, NAME - 1)))
				error(MALLOC, errno, "data->cont");
		} else if (opt == 'u') {
			if (!(data->ddns = strndup(optarg, GROUP - 1)))
				error(MALLOC, errno, "data->ddns");
		} else if (opt == 'x') {
			data->boot = 0;
		} else if (opt == 'd') {
			if (!(data->domain = strndup(optarg, DOMAIN - 1)))
				error(MALLOC, errno, "data->domain");
		} else if (opt == 'e') {
			if (!(data->ether = strndup(optarg, NAME - 1)))
				error(MALLOC, errno, "data->ether");
		} else if (opt == 'g') {
			if (!(data->gw = strndup(optarg, INET6_ADDRSTRLEN - 1)))
				error(MALLOC, errno, "data->gw");
		} else if (opt == 'i') {
			if (!(data->ipaddr = strndup(optarg, INET6_ADDRSTRLEN - 1)))
				error(MALLOC, errno, "data->ipaddr");
		} else if (opt == 'a') {
			if (!(data->name = strndup(optarg, CANAME - 1)))
				error(MALLOC, errno, "data->name");
		} else if (opt == 'k') {
			if (!(data->netb = strndup(optarg, INET6_ADDRSTRLEN - 1)))
				error(MALLOC, errno, "data->netb");
		} else if (opt == 'm') {
			if (!(data->netm = strndup(optarg, INET6_ADDRSTRLEN - 1)))
				error(MALLOC, errno, "data->netm");
		} else if (opt == 'o') {
			if (!(data->ou = strndup(optarg, CANAME - 1)))
				error(MALLOC, errno, "data->ou");
		} else if (opt == 'f') {
			if (!(data->filename = strndup(optarg, FILES - 1)))
				error(MALLOC, errno, "data->filename");
		} else if (opt == 'h') {
			data->action = ACT_HELP;
		} else if (opt == 't') {
			data->action = ACT_HOST;
		} else if (opt == 'n') {
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
	if (!(data->basedn)) {
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
		} else if (!(data->gw)) {
			what = "gateway";
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
		} else if (!(data->domain)) {
			what = "domain";
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
	if (!(who) || !(what))
		return;
	else if (strncmp(who, "all", 4) == 0)
		fprintf(stderr, "\
Adding any configuration needs a %s\n", what);
	else
		fprintf(stderr, "\
Adding a %s configuration needs a %s\n", who, what);
}

static void
output_dhcp_host_ldif(lcdhcp_s *data)
{
	FILE *out;
	char *container;
	if (!(data))		// Sanity check
		return;
	if (data->filename) {
		if (!(out =  fopen(data->filename, "w")))
			fprintf(stderr, "Cannot open %s for reading!\n", data->filename);
	} else {
		out = stdout;
	}
	if (data->cont)
		container = strndup(data->cont, NAME - 1);
	else
		container = strndup("dhcp", NAME - 1);
	fprintf(out, "\
# %s, %s, %s\n\
dn: cn=%s,cn=%s,%s\n\
cn: %s\n\
objectClass: top\n\
%s\n\
%s\n\
%s: ethernet %s\n\
%s: fixed-address %s\n\
%s: domain-name \"%s\"\n",
data->name, container, data->basedn, data->name, container, data->dn,
data->name, dp_shr_net, dp_opt, dh_mac, data->ether, dh_stmt, data->ipaddr,
dh_stmt, data->domain);
	if (out != stdout)
		fclose(out);
	free(container);
}
