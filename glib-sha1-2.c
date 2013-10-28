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
	const gchar *pass;
	int retval;
	guchar mess[] = "MyPa55w0rd", out[20];
	gchar *conv;
	GChecksum *sum;
	
	sum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(sum, mess, -1);
	pass = g_checksum_get_string(sum);
	if ((retval = hex_conv(pass, out)) != NONE) {
		printf("Conversion failed!\n");
		g_checksum_free(sum);
		exit (ONE);
	}
	conv = g_base64_encode(out, 20);
	printf("%s\n", conv);
	g_checksum_free(sum);
	g_free(conv);
	return NONE;
}
