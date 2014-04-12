#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <openssl/sha.h>

int
main ()
{
	int rd = open("/dev/random", O_RDONLY), i;
	guchar md[SHA_DIGEST_LENGTH], salt[7], *np, newp[26];
	const guchar pass[] = "MyPa55w0rd";
	gchar *out;
	SHA_CTX msg;

	SHA1(pass, 10, md);
	/* Overkill. Can easily use a PRNG here */
	if ((read(rd, &salt, 7)) != 7) {
		close(rd);
		printf("Could not read enough random data\n");
		exit (2);
	}
	close(rd);
/*	SHA1_Final(md, &msg); */
/*	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02x", md[i]); 
	printf("\n"); */
	out = g_base64_encode(md, 20);
	printf("{SHA}%s\n", out);
	g_free(out);
	np = newp;
	SHA1_Init(&msg);
	SHA1_Update(&msg, pass, 10);
	SHA1_Update(&msg, salt, 6);
	SHA1_Final(md, &msg);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		*(np + i) = *(md + i);
	for (i = 0; i < 6; i++)
		*(np + i + 20) = salt[i];
	out = g_base64_encode(np, 26);
	printf("{SSHA}%s\n", out);
	g_free(out);
	return 0;
}
