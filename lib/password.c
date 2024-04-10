/*
 *
 *  ldap-col: collection of ldap utilities
 *  Copyright (C) 2014  Iain M Conochie <iain-AT-thargoid.co.uk>
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
 *  password.c
 * 
 *  Contains the sha function for generating passwords for slapd
 *  and also various other functions. Part of the ailsaldap library
 * 
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <ailsaldap.h>

void
split_name(inp_data_s *data)
{
	char *work, *tmp, *pos = 0;
	int c = NONE, len = NONE; /* c counts names */
	unsigned char f = NONE, s = NONE; /* first letter of (f)irst and (s)urname */

	if (!(data->uname = calloc(SURNAME, sizeof(char))))
		error(MALLOC, errno, "data->uname in split_name");
	work = strndup(data->name, USERL);
	tmp = work;
	while ((tmp = strchr(tmp, ' '))) {
		c++;
		tmp++;
	}
	tmp = work;
	if (c < 1) {
		fprintf(stderr, "No surname or first name provided\n");
		free(work);
		clean_lcu_data(data);
		exit(1);
	} else if (c < 2) { /* No middle name. Wierdo! */
		tmp = strchr(tmp, ' ');
		*tmp = '\0';
		tmp++;
		if (!(data->fname = strndup(work, SURNAME)))
			error(MALLOC, errno, "data->fname");
		if (!(data->sur = strndup(tmp, SURNAME)))
			error(MALLOC, errno, "data->sur");
	} else { /* We have a middle name */
		tmp = strchr(tmp, ' ');
		*tmp = '\0';
		tmp++;
		if (!(data->fname = strndup(work, SURNAME)))
			error(MALLOC, errno, "data->fname");
		while ((tmp = strchr(tmp, ' ')))
			pos = ++tmp;
		if (!(data->sur = strndup(pos, SURNAME)))
			error(MALLOC, errno, "data->sur");
	}
	pos = data->sur;
	pos++;
	f = tolower(*(data->fname));
	s = tolower(*(data->sur));
	if (data->lu > NONE) {/* Long format username */
		if ((len = snprintf(data->uname, SURNAME, "%c%c%s",
		 f, s, pos)) > SURNAME)
			fprintf(stderr, "Username truncated by %d!\n",
				(len - SURNAME) + 1);
	} else {
		pos = data->fname;
		pos++;
		if ((len = snprintf(data->uname, SURNAME, "%c%s",
		 f, pos)) > SURNAME)
			fprintf(stderr, "Username truncated by %d!\n",
				(len - SURNAME) + 1);
	}
	*(data->fname) = toupper(*(data->fname));
	free(work);
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
	fprintf(stderr, "%s", message);
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
	pass[i] = '\0';

	/*resetting our old STDIN_FILENO*/ 
	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
	fprintf(stderr, "\n");
	return pass;
}

int
output_hex_conversion(unsigned char *string, const char *hash)
{
	char *output;
	int retval = 0;
	size_t len, i;

	if (strncmp(hash, "sha1", 4) == 0)
		len = 20;
	else
		return 1;
	if (!(output = calloc(1, DOMAIN)))
		rep_err("output in output_hex_conversion");
	for (i = 0; i < len; i++)
		printf("%02x:", string[i]);
	printf("\n");
	free(output);
	return retval;
}

