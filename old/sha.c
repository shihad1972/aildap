#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

void
rep_err(const char *msg)
{
	fprintf(stderr, "Cannot malloc %s\n", msg);
	exit(1);
}

void
sha_err(const char *msg)
{
	fprintf(stderr, "Problem with %s\n", msg);
	exit(2);
}
int
main()
{
	SHA_CTX *ctx = '\0';
	unsigned char pass[] = "password";
	unsigned long len = 8;

	if (!(ctx = malloc(sizeof(SHA_CTX))))
		rep_err("ctx in main");
	if ((SHA1_Init(ctx)) != 1)
		sha_err("initialising ctx");
	
}
