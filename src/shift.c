#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ailsaldap.h>

int
main()
{
        unsigned int shift = 8;
        const unsigned char *str = (const unsigned char *)"This will be the text to encode";
        unsigned char *b64, *b64d;
        size_t len = strlen((const char *)str);

        printf("Shift is: %u\n", shift);
        shift = shift << 2;
        printf("shift is now: %u\n", shift);
        printf("Original text: %s\n", str);
        b64 = ailsa_b64_encode(str, len);
        printf("Base64 Encdoded text: %s\n", b64);
        b64d = ailsa_b64_decode(b64);
        if (!(b64d)) {
                fprintf(stderr, "decode failed!");
                exit(1);
        }
        printf("Decode text: %s\n", b64d);
        free(b64);
        free(b64d);
        return 0;
}
