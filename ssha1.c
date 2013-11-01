#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include "base-sha.h"

int
/*main (int argc, char *argv[]) */
main()
{
	int rd = open("/dev/random", O_RDONLY), i;
	GChecksum *sum, *nsum;
	gchar *pass;
	gsize slen = 20;
	const guchar mypass[] = "MyPa55w0rd", salt[6];
	guint8 *output;

	if (!(output = malloc(26 * sizeof(char))))
		exit (1);
	if ((read(rd, &salt, 6)) != 6) {
		close(rd);
		printf("Could not read enough random data\n");
		exit (2);
	}
	close(rd);
	sum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(sum, mypass, -1);
	g_checksum_get_digest(sum, output, &slen);
	g_checksum_free(sum);
	pass = g_base64_encode(output, 20);
	printf("{SHA}%s\n", pass);
	g_free(pass);
	nsum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(nsum, mypass, -1);
	g_checksum_update(nsum, salt, 6);
	g_checksum_get_digest(nsum, output, &slen);
	for (i = 0; i < 6; i++)
		*(output + 20 + i) = salt[i];
	pass = g_base64_encode(output, 26);
	printf("{SSHA}%s\n", pass);
	g_free(pass);
	g_checksum_free(nsum);
	free(output);
	return 0;
}