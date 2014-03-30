/*
 * user.c: (C) 2013 Iain M Conochie
 * 
 * Main function for the program to create user entries in the ldap
 * directory
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ldap-col.h"
#include "base-sha.h"

int
parse_command_line(int argc, char *argv[], inp_data_s *data)
{
	int opt = NONE, slen = NONE;

	while ((opt = getopt(argc, argv, "d:gln:pu:")) != -1) {
		if (opt == 'd') {
			GET_OPT_ARG(dom, DOMAIN, Domain)
		} else if (opt == 'g') {
			data->gr = ONE;
		} else if (opt == 'l') {
			data->lu = ONE;
		} else if (opt == 'p') {
			data->np = ONE;
		} else if (opt == 'n') {
			GET_OPT_ARG(name, USER, Name)
		} else if (opt == 'u') {
			if (optarg)
				data->user = (short)strtoul(optarg, NULL, DECIMAL);
			else
				fprintf(stderr, "No userid specified\n");
		} else {
			comm_line_err(argv[0]);
			return ONE;
		}
	}
	if (strlen(data->dom) == 0) {
		fprintf(stderr, "No domain specified\n");
		comm_line_err(argv[0]);
		exit (1);
	} else if (strlen(data->name) == 0) {
		fprintf(stderr, "No name specified\n");
		comm_line_err(argv[0]);
		exit (1);
	} else if (data->user == 0) {
		fprintf(stderr, "No userid specified\n");
		comm_line_err(argv[0]);
		exit (1);
	}
	return NONE;
}

int
main (int argc, char *argv[])
{
	char *pass/*, *npass */;
	int retval = 0;
	inp_data_s *data;

	if (!(data = malloc(sizeof(inp_data_s))))
		rep_err("data in main");
	init_lcu_data(data);
	parse_command_line(argc, argv, data);
	split_name(data);
	if (data->np == 0) {
		pass = getPassword("Enter password for user: ");
		snprintf(data->pass, DOMAIN, "%s", pass);
		free(pass);
	}
	output_ldif(data);
	clean_lcu_data(data);
	return retval;
}
