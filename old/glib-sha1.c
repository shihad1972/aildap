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
	GHmac *mac;
	gint retval = NONE;
	gchar out[64], *gout;
	guchar mess[] = "MyPa55w0rd", buff[20];

	gout = out;
	mac = g_hmac_new(G_CHECKSUM_SHA1, mess, sizeof(mess));
	g_hmac_update(mac, buff, 20);
	gout = g_base64_encode(buff, 20);
	printf("%s\n", gout);
	exit (retval);
}
