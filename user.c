#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "base-sha.h"

int
main ()
{
	char *pass/*, *npass */;
	int retval = 0;

	pass = getPassword("Enter your password: ");
	free(pass);
	return retval;
}
