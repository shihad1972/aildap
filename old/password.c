#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
/* #include <glib.h> */
#include "base-sha.h"

int
main()
{
	char salt[] = "$6$65yrxskx$", *pass;

	if (!(pass = malloc(64)))
		rep_err("Cannot malloc pass");
	pass = getpass("Enter a password: ");
	printf("\nPassword was: %s\n", pass);
	free(pass);
	return 0;
}