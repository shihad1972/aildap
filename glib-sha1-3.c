#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include "base-sha.h"

int
/*main (int argc, char *argv[]) */
main()
{
	GChecksum *sum;
	gchar *pass;
	const guchar mypass[] = "MyPa55w0rd";
	guint8 *output;
	gsize slen = 20;

	if (!(output = malloc(20 * sizeof(char))))
		exit (1);
	sum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(sum, mypass, -1);
	g_checksum_get_digest(sum, output, &slen);
	pass = g_base64_encode(output, 20);
	printf("%s\n", pass);
	g_free(pass);
	free(output);
	return 0;
}