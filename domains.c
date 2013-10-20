#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

int
main ()
{
	int i;
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned char pass[] = "MyP@55w0rd";
/*	SHA_CTX msg; */

/*	SHA1_Init(&msg); */
	SHA1(pass, strlen(pass), md);
/*	SHA1_Final(md, &msg); */
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02x", md[i]);
	printf("\n");
	return 0;
}
