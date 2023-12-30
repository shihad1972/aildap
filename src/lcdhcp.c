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
#include <syslog.h>
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
	ACT_HOST = 5,
	ACT_LDAP_ADD = 6
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

static int
add_dhcpd_ldap(lcdhcp_s *data);

static int
add_dhcpd_ldap_host(lcdhcp_s *data);

static int
fill_dhcpd_ldap_host(lcdhcp_s *data, LDAPMod **mod);

static int
add_dhcpd_ldap_network(lcdhcp_s *data);

static int
fill_dhcpd_ldap_shared_network(lcdhcp_s *data, LDAPMod **mods);

static int
fill_dhcpd_ldap_subnet(lcdhcp_s *data, LDAPMod **mods);

static int
add_dhcpd_ldap_server(lcdhcp_s *data);

static int
fill_dhcp_ldap_server(lcdhcp_s *data, LDAPMod **mods);

static int
fill_dhcp_ldap_service(lcdhcp_s *data, LDAPMod **mods);

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
	dhcp->boot = 1;
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
	else if (dhcp->ldap)
		retval = add_dhcpd_ldap(dhcp);
	else if ((dhcp->action == ACT_HOST) && !(dhcp->ldap))
		output_dhcp_host_ldif(dhcp);
	else if ((dhcp->action == ACT_SERVER) && !(dhcp->ldap))
		output_dhcp_server_ldif(dhcp);
	else if ((dhcp->action == ACT_NET) && !(dhcp->ldap))
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
	config->url = get_value_from_kv_list(list, "url");
	config->user = get_value_from_kv_list(list, "user");
	config->pass = get_value_from_kv_list(list, "pass");
}

static int
parse_lcdhcp_command_line(int argc, char *argv[], lcdhcp_s *data)
{
	int opt;
	int retval = 0;
	const char *optstr = "b:l:r:u:xd:e:f:g:i:n:k:m:o:ahtwsv";
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
		{"url",			required_argument,	NULL,	'u'},
		{"disable-booting",	no_argument,		NULL,	'x'},
		{"add-ldap",		no_argument,		NULL,	'a'},
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
			data->url = optarg;
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
		} else if (opt == 'o') {
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
		} else if (opt == 'a') {
			data->ldap = ONE;
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
	const char *ou = "dhcp";
	const char *bfile = "pxelinux.cfg";
	const char *who = NULL, *what = NULL;

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
	if (!(data->ou))
		data->ou = ou;
	if (data->boot && !(data->bfile))
		data->bfile = bfile;
	if (data->filename && data->ldap) {
		ailsa_syslog(LOG_DAEMON, "-a and -f options are mutually exclusive");
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
		if (data->boot && !(data->bserver)) {
			ailsa_syslog(LOG_DAEMON, "booting enabled by default; provide boot server with -r");
			goto cleanup;
		}
		if (!(data->netb)) {
			what = "Network block";
			goto cleanup;
		} else if (!(data->netm)) {
			what = "Netmask";
			goto cleanup;
		}
		if ((!(data->ipaddr) && (data->domain)) || (!(data->domain) && (data->ipaddr))) {
			ailsa_syslog(LOG_DAEMON, "only one of -i and -d provided, both are required to add a DNS domain to a network");
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
%s: ddns-update-style none\n",
data->ou, data->dn, data->ou, data->dn, obcl_top, dp_service,
dh_pri_dn, data->ou, data->dn, dh_stmt);
	if (data->boot)
		fprintf(out, "\
%s: allow booting\n\
%s: allow bootp\n", dh_stmt, dh_stmt);
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
%s\n", data->name, data->ou, data->dn, data->name,
data->ou, data->dn, data->name, obcl_top, dp_shr_net);
	if ((data->ipaddr && data->domain) || data->gw) {
		fprintf(out, "\
%s\n", dp_opt);
		if (data->ipaddr && data->domain)
			fprintf(out, "\
%s: domain-name-servers %s\n\
%s: domain-search \"%s\"\n", dh_opt, data->ipaddr, dh_opt, data->domain);
		if (data->gw)
			fprintf(out, "\
%s: routers %s\n", dh_opt, data->gw);
	}
	fprintf(out, "\n");
	fprintf(out, "\
# %s, %s, %s, %s\n\
dn: cn=%s,cn=%s,cn=service,ou=%s,%s\n\
cn: %s\n\
%s\n\
%s\n\
%s: %s\n\
%s: authoratative\n", data->netb, data->name, data->ou, data->dn,
data->netb, data->name, data->ou, data->dn, data->netb, obcl_top, dp_subnet,
dh_netmask, data->netm, dh_stmt);
	if (data->boot)
		fprintf(out, "\
%s: next-server %s\n\
%s: filename \"%s\"\n", dh_stmt, data->bserver, dh_stmt, data->bfile);
	if (out != stdout)
		fclose(out);
}

/*
 * Start of trying to add data directly to the ldap server
 * wish me luck
 */

static int
add_dhcpd_ldap(lcdhcp_s *data)
{
	int retval = 0;

	if (!(data))
		return AILSA_NO_DATA;
	if (data->action == ACT_HOST)
		retval = add_dhcpd_ldap_host(data);
	else if (data->action == ACT_NET)
		retval = add_dhcpd_ldap_network(data);
	else if (data->action == ACT_SERVER)
		retval = add_dhcpd_ldap_server(data);
	return retval;
}

static int
add_dhcpd_ldap_host(lcdhcp_s *dhcp)
{
	int retval = 0;
	char *dn = ailsa_calloc(RBUFF_S, "dn in add_dhcpd_ldap_host");
	LDAP *ld = NULL;
	LDAPMod **mod = ailsa_calloc(sizeof(mod) * AILSA_DHCP_HOST, "mod in add_dhcpd_ldap_host"); // ** HARDCODED **

	snprintf(dn, RBUFF_S, "cn=%s,ou=%s,%s", dhcp->name, dhcp->ou, dhcp->dn);
	ailsa_ldap_init(&ld, dhcp->url);
	if ((retval = fill_dhcpd_ldap_host(dhcp, mod)) != 0)
		goto cleanup;
	if ((retval = ldap_simple_bind_s(ld, dhcp->user, dhcp->pass)) != LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "bind failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	if ((retval = ldap_add_ext_s(ld, dn, mod, NULL, NULL))!= LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "Adding failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	cleanup:
		ldap_mods_free(mod, ONE);
		if (ld)
			ldap_unbind(ld);
		my_free(dn);
		return retval;
}

static int
fill_dhcpd_ldap_host(lcdhcp_s *data, LDAPMod **mods)
{
	char **values;
	int retval = 0;
	LDAPMod *mod;

	mods[0] = ailsa_calloc(sizeof(LDAPMod), "mods[0] in fill_dhcpd_ldap_host");
	mod = mods[0];
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values in fill_dhcpd_ldap_host");
	mod->mod_type = strdup("cn");
	mod->mod_values = values;
	values[0] = strndup(data->name, RBUFF_S);
	mods[1] = ailsa_calloc(sizeof(LDAPMod), "mods[1] in loop in fill_dhcpd_ldap_host");
	mod = mods[1];
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values in fill_dhcpd_ldap_host");
	mod->mod_type = strdup("objectclass");
	mod->mod_values = values;
	values[0] = strdup("top");
	values[1] = strdup("dhcpHost");
	values[2] = strdup("dhcpOptions");
	mods[2] = ailsa_calloc(sizeof(LDAPMod), "mods[2] in loop in fill_dhcpd_ldap_host");
	mod = mods[2];
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values in fill_dhcpd_ldap_host");
	mod->mod_type = strdup("dhcpHWAddress");
	mod->mod_values = values;
	values[0] = ailsa_calloc(RBUFF_S, "values[0] in fill_dhcpd_ldap_host");
	snprintf(values[0], RBUFF_S, "ethernet %s", data->ether);
	mods[3] = ailsa_calloc(sizeof(LDAPMod), "mods[3] in loop in fill_dhcpd_ldap_host");
	mod = mods[3];
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values in fill_dhcpd_ldap_host");
	mod->mod_type = strdup("dhcpStatements");
	mod->mod_values = values;
	values[0] = ailsa_calloc(RBUFF_S, "values[0] in fill_dhcpd_ldap_host");
	snprintf(values[0], RBUFF_S, "fixed-address %s", data->ipaddr);
	if (data->domain) {
		values[1] = ailsa_calloc(RBUFF_S, "values[1] in fill_dhcpd_ldap_host");
		snprintf(values[1], RBUFF_S, "domain-name \"%s\"", data->domain);
	}
	return retval;
}

static int
add_dhcpd_ldap_network(lcdhcp_s *dhcp)
{
	int retval = 0;
	LDAP *ld = NULL;
	char *shr_dn = ailsa_calloc(RBUFF_S, "shr_dn in add_dhcpd_ldap_network");
	char *sub_dn = ailsa_calloc(RBUFF_S, "sub_dn in add_dhcpd_ldap_network");
	LDAPMod **shr = ailsa_calloc(sizeof(shr) * AILSA_DHCP_NET, "shr in add_dhcpd_ldap_network"); // ** HARDCODED **
	LDAPMod **sub = ailsa_calloc(sizeof(sub) * AILSA_DHCP_NET, "sub in add_dhcpd_ldap_network");

	if (!(dhcp)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}
	snprintf(shr_dn, RBUFF_S, "cn=%s,cn=service,ou=%s,%s", dhcp->name, dhcp->ou, dhcp->dn);
	snprintf(sub_dn, RBUFF_S, "cn=%s,cn=%s,cn=service,ou=%s,%s", dhcp->netb, dhcp->name, dhcp->ou, dhcp->dn);
	ailsa_ldap_init(&ld, dhcp->url);
	if ((retval = fill_dhcpd_ldap_shared_network(dhcp, shr)) != 0)
		goto cleanup;
	if ((retval = fill_dhcpd_ldap_subnet(dhcp, sub)) != 0)
		goto cleanup;
	if ((retval = ldap_simple_bind_s(ld, dhcp->user, dhcp->pass)) != LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "bind failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	if ((retval = ldap_add_ext_s(ld, shr_dn, shr, NULL, NULL))!= LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "Adding shared network failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	if ((retval = ldap_add_ext_s(ld, sub_dn, sub, NULL, NULL)) != LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "Adding subnet failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	cleanup:
		ldap_mods_free(shr, ONE);
		ldap_mods_free(sub, ONE);
		if (ld)
			ldap_unbind(ld);
		my_free(shr_dn);
		my_free(sub_dn);
		return retval;
}

static int
fill_dhcpd_ldap_shared_network(lcdhcp_s *dhcp, LDAPMod **mods)
{
	int retval = 0;
	char **values = NULL;

	if (!(dhcp) || !(mods)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}

	mods[0] = ailsa_calloc(sizeof(LDAPMod), "mods[0] in fill_dhcpd_ldap_shared_network");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[0] in fill_dhcpd_ldap_shared_network");
	mods[0]->mod_type = strdup("cn");
	mods[0]->mod_values = values;
	values[0] = strndup(dhcp->name, RBUFF_S);

	mods[1] = ailsa_calloc(sizeof(LDAPMod), "mods[1] in fill_dhcpd_ldap_shared_network");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[1] in fill_dhcpd_ldap_shared_network");
	mods[1]->mod_type = strdup("objectClass");
	mods[1]->mod_values = values;
	values[0] = strdup("top");
	values[1] = strdup("dhcpSharedNetwork");
	if (dhcp->domain && dhcp->ipaddr) {
		values[2] = strdup("dhcpOptions");
		mods[2] = ailsa_calloc(sizeof(LDAPMod), "mods[2] in fill_dhcpd_ldap_shared_network");
		values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[2] in fill_dhcpd_ldap_shared_network");
		mods[2]->mod_type = strdup("dhcpOption");
		mods[2]->mod_values = values;
		values[0] = ailsa_calloc(RBUFF_S, "values[0] for mods[2] in fill_dhcpd_ldap_shared_network");
		snprintf(values[0], RBUFF_S, "domain-name-servers %s", dhcp->ipaddr);
		values[1] = ailsa_calloc(RBUFF_S, "values[1] for mods[2] in fill_dhcpd_ldap_shared_network");
		snprintf(values[1], RBUFF_S, "domain-search \"%s\"", dhcp->domain);
	}
	cleanup:
		return retval;
}

static int
fill_dhcpd_ldap_subnet(lcdhcp_s *dhcp, LDAPMod **mods)
{
	int retval = 0;
	char ** values = NULL;

	if (!(dhcp) || !(mods)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}
	mods[0] = ailsa_calloc(sizeof(LDAPMod), "mods[0] in fill_dhcpd_ldap_subnet");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[0] in fill_dhcpd_ldap_subnet");
	mods[0]->mod_type = strdup("cn");
	mods[0]->mod_values = values;
	values[0] = strndup(dhcp->netb, RBUFF_S);

	mods[1] = ailsa_calloc(sizeof(LDAPMod), "mods[1] in fill_dhcpd_ldap_subnet");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[1] in fill_dhcpd_ldap_subnet");
	mods[1]->mod_type = strdup("objectClass");
	mods[1]->mod_values = values;
	values[0] = strdup("top");
	values[1] = strdup("dhcpSubnet");

	mods[2] = ailsa_calloc(sizeof(LDAPMod), "mods[2] in fill_dhcpd_ldap_subnet");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[2] in fill_dhcpd_ldap_subnet");
	mods[2]->mod_type = strdup("dhcpNetMask");
	mods[2]->mod_values = values;
	values[0] = strndup(dhcp->netm, RBUFF_S);

	mods[3] = ailsa_calloc(sizeof(LDAPMod), "mods[3] in fill_dhcpd_ldap_subnet");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[3] in fill_dhcpd_ldap_subnet");
	mods[3]->mod_type = strdup("dhcpStatements");
	mods[3]->mod_values = values;
	values[0] = strdup("authoratative");
	if (dhcp->boot && dhcp->bserver) {
		values[1] = ailsa_calloc(RBUFF_S, "values[1] for mods[3] in fill_dhcpd_ldap_subnet");
		snprintf(values[1], RBUFF_S, "next-server %s", dhcp->bserver);
		values[2] = ailsa_calloc(RBUFF_S, "values[2] for mods[3] in fill_dhcpd_ldap_subnet");
		snprintf(values[2], RBUFF_S, "filename \"%s\"", dhcp->bfile);
	}
	cleanup:
		return retval;
}

static int
add_dhcpd_ldap_server(lcdhcp_s *dhcp)
{
	int retval = 0;
	LDAP *ld = NULL;
	char *server_dn = ailsa_calloc(RBUFF_S, "server_dn in add_dhcpd_ldap_server");
	char *service_dn = ailsa_calloc(RBUFF_S, "service_dn in add_dhcpd_ldap_server");
	LDAPMod **ver = ailsa_calloc(sizeof(ver) * AILSA_DHCP_SERVICE, "ver in add_dhcpd_ldap_server");
	LDAPMod **ice = ailsa_calloc(sizeof(ver) * AILSA_DHCP_SERVICE, "ice in add_dhcpd_ldap_server");

	if (!(dhcp)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}
	snprintf(server_dn, RBUFF_S, "cn=%s,ou=%s,%s", dhcp->name, dhcp->ou, dhcp->dn);
	snprintf(service_dn, RBUFF_S, "cn=service,ou=%s,%s", dhcp->ou, dhcp->dn);
	ailsa_ldap_init(&ld, dhcp->url);
	if ((retval = fill_dhcp_ldap_server(dhcp, ver)) != 0)
		goto cleanup;
	if ((retval = fill_dhcp_ldap_service(dhcp, ice)) != 0)
		goto cleanup;
	if ((retval = ldap_simple_bind_s(ld, dhcp->user, dhcp->pass)) != LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "bind failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	if ((retval = ldap_add_ext_s(ld, server_dn, ver, NULL, NULL)) != LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "Adding DHCP server failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	if ((retval = ldap_add_ext_s(ld, service_dn, ice, NULL, NULL)) != LDAP_SUCCESS) {
		ailsa_syslog(LOG_DAEMON, "Adding DHCP service failed with %s", ldap_err2string(retval));
		goto cleanup;
	}
	cleanup:
		ldap_mods_free(ver, ONE);
		ldap_mods_free(ice, ONE);
		if (ld)
			ldap_unbind(ld);
		my_free(server_dn);
		my_free(service_dn);
		return retval;
}

static int
fill_dhcp_ldap_server(lcdhcp_s *dhcp, LDAPMod **mods)
{
	int retval = 0;
	char **values = NULL;

	if (!(dhcp) || !(mods)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}

	mods[0] = ailsa_calloc(sizeof(LDAPMod), "mods[0] in fill_dhcp_ldap_server");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[0] in fill_dhcp_ldap_server");
	mods[0]->mod_type = strdup("cn");
	mods[0]->mod_values = values;
	values[0] = strndup(dhcp->name, RBUFF_S);

	mods[1] = ailsa_calloc(sizeof(LDAPMod), "mods[1] in fill_dhcp_ldap_server");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[1] in fill_dhcp_ldap_server");
	mods[1]->mod_type = strdup("objectClass");
	mods[1]->mod_values = values;
	values[0] = strdup("top");
	values[1] = strdup("dhcpServer");

	mods[2] = ailsa_calloc(sizeof(LDAPMod), "mods[2] in fill_dhcp_ldap_server");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[2] in fill_dhcp_ldap_server");
	mods[2]->mod_type = strdup("dhcpServiceDn");
	mods[2]->mod_values = values;
	values[0] = ailsa_calloc(RBUFF_S, "values[0] for mods[2] in fill_dhcp_ldap_server");
	snprintf(values[0], RBUFF_S, "cn=service,ou=%s,%s", dhcp->ou, dhcp->dn);

	cleanup:
		return retval;
}

static int
fill_dhcp_ldap_service(lcdhcp_s *dhcp, LDAPMod **mods)
{
	char **values;
	int retval = 0;

	if (!(dhcp) || !(mods)) {
		retval = AILSA_NO_DATA;
		goto cleanup;
	}

	mods[0] = ailsa_calloc(sizeof(LDAPMod), "mods[0] in fill_dhcp_ldap_service");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[0] in fill_dhcp_ldap_service");
	mods[0]->mod_type = strdup("cn");
	mods[0]->mod_values = values;
	values[0] = strdup("service");

	mods[1] = ailsa_calloc(sizeof(LDAPMod), "mods[1] in fill_dhcp_ldap_service");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[1] in fill_dhcp_ldap_service");
	mods[1]->mod_type = strdup("objectClass");
	mods[1]->mod_values = values;
	values[0] = strdup("top");
	values[1] = strdup("dhcpService");

	mods[2] = ailsa_calloc(sizeof(LDAPMod), "mods[2] in fill_dhcp_ldap_service");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[2] in fill_dhcp_ldap_service");
	mods[2]->mod_type = strdup("dhcpPrimaryDn");
	mods[2]->mod_values = values;
	values[0] = ailsa_calloc(RBUFF_S, "values[0] for mods[2] in fill_dhcp_ldap_service");
	snprintf(values[0], RBUFF_S, "cn=%s,ou=%s,%s", dhcp->name, dhcp->ou, dhcp->dn);

	mods[3] = ailsa_calloc(sizeof(LDAPMod), "mods[3] in fill_dhcp_ldap_service");
	values = ailsa_calloc(sizeof(values) * AILSA_DHCPD_CLASS, "values for mods[3] in fill_dhcp_ldap_service");
	mods[3]->mod_type = strdup("dhcpStatements");
	mods[3]->mod_values = values;
	values[0] = strdup("ddns-update-style none");
	if (dhcp->boot) {
		values[1] = strdup("allow booting");
		values[2] = strdup("allow bootp");
	}
	cleanup:
		return retval;
}
