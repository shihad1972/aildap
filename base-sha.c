#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <termios.h> 
#include "base-sha.h"


void
rep_err(const char *error)
{
	fprintf(stderr, "%s\n", error);
	exit (MEM);
}

int
init_input_data(inp_data_s *data) 
{
	if (!data)
		return ONE;
	data->gr = data->lu = data->user = NONE;
	data->dom = data->pass = data->sur = data->name = '\0';
	MALLOC_DATA_MEMBER(dom, DOMAIN);
	MALLOC_DATA_MEMBER(pass, DOMAIN);
	MALLOC_DATA_MEMBER(sur, SURNAME);
	MALLOC_DATA_MEMBER(name, USER);
	return NONE;
}

void
clean_data(inp_data_s *data)
{
	if (!data)
		exit (MEM);
	CLEAN_DATA_MEMBER(dom)
	CLEAN_DATA_MEMBER(pass)
	CLEAN_DATA_MEMBER(sur)
	CLEAN_DATA_MEMBER(name)
	free(data);
}

int
parse_command_line(int argc, char *argv[], inp_data_s *data)
{
	int opt = NONE, slen = NONE;

	while ((opt = getopt(argc, argv, "d:gln:s:u:")) != -1) {
		if (opt == 'd') {
			GET_OPT_ARG(dom, DOMAIN, Domain)
		} else if (opt == 'g') {
			data->gr = ONE;
		} else if (opt == 'l') {
			data->lu = ONE;
		} else if (opt == 'n') {
			GET_OPT_ARG(name, USER, Name)
		} else if (opt == 's') {
			GET_OPT_ARG(sur, SURNAME, Surname)
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
	} else if (strlen(data->sur) == 0) {
		fprintf(stderr, "No surname specified\n");
		comm_line_err(argv[0]);
		exit (1);
	} else if (data->user == 0) {
		fprintf(stderr, "No userid specified\n");
		comm_line_err(argv[0]);
		exit (1);
	}
	return NONE;
}

char *
getPassword(const char *message)
{
	static struct termios oldt, newt;
	int i = 0;
	int c;
	char *pass;

	if (!(pass = malloc(PASS_SIZE)))
		exit (2);
	printf("%s", message);
	/*saving the old settings of STDIN_FILENO and copy settings for resetting*/
	tcgetattr( STDIN_FILENO, &oldt);
	newt = oldt;

	/*setting the approriate bit in the termios struct*/
	newt.c_lflag &= ~(ECHO);  

	/*setting the new bits*/
	tcsetattr( STDIN_FILENO, TCSANOW, &newt);

	/*reading the password from the console*/
	while ((c = getchar())!= '\n' && c != EOF && i < (PASS_SIZE - 1))
		pass[i++] = c;
	printf("\n");
	pass[i] = '\0';

	/*resetting our old STDIN_FILENO*/ 
	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
	return pass;
}

void
comm_line_err(char *prog)
{
	fprintf(stderr, "\
Usage: %s -d domain [ -g ] [ -l ] -n name -s surname -u userid\n\
-g: create group for the user (same name and id)\n\
-l: create long user name (first initial plus surname\n", prog);
}

/*
int
hex_conv(const char *pass, guchar *out)
{
	int retval = NONE;
	gsize olen = strlen(out), x;
	for (x = 0; x < olen; x++) {
		sscanf(pass + 2*x, "%02x", &out[x]);
	}
	return retval;
}
*/
