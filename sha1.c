#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

int
/*main (int argc, char *argv[]) */
main ()
{
	EVP_MD_CTX *msg;
	const EVP_MD *md;
	char mess[] = "MyP@55w0rd";
	char type[] = "sha";
	int i;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(type);
	if (!md) {
		printf("Unknown digest %s!\n", type);
		exit(1);
	}
	msg = EVP_MD_CTX_create();
	EVP_DigestInit_ex(msg, md, NULL);
	EVP_DigestUpdate(msg, mess, strlen(mess));
	EVP_DigestFinal_ex(msg, md_value, &md_len);
	EVP_MD_CTX_destroy(msg);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02x", md_value[i]);
/*	printf("\n"); */

	return 0;
}
