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
#include "base-sha.h"

int
main (int argc, char *argv[])
{
	char *pass/*, *npass */;
	int retval = 0;
	inp_data_s *data;

	if (!(data = malloc(sizeof(inp_data_s))))
		rep_err("data in main");
	init_input_data(data);
	parse_command_line(argc, argv, data);
	split_name(data);
	if (data->np == 0) {
		pass = getPassword("Enter password for user: ");
		snprintf(data->pass, DOMAIN, "%s", pass);
		free(pass);
	}
	output_ldif(data);
	clean_data(data);
	return retval;
}
