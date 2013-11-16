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
	BIO *bio, *b64;
	EVP_MD_CTX *msg;
	const EVP_MD *md;
	char mess[] = "password";
	char type[] = "sha1";
	int retval = 0;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	printf("Password size: %zu\n", strlen(mess));
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
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
	BIO_write(bio, md_value, SHA_DIGEST_LENGTH);
	retval = BIO_flush(bio);
	BIO_free_all(bio);

	return retval;
}
