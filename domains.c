#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <openssl/sha.h>

int
main ()
{
	/*int i; */
	unsigned char md[SHA_DIGEST_LENGTH];
	const guchar pass[] = "MyPa55w0rd";
	gchar *out;
/*	SHA_CTX msg; */

/*	SHA1_Init(&msg); */
	SHA1(pass, 10, md);
/*	SHA1_Final(md, &msg); */
/*	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02x", md[i]); 
	printf("\n"); */
	out = g_base64_encode(md, 20);
	printf("%s\n", out);
	return 0;
}
