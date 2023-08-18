#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "../include/ailsaldap.h"
START_TEST(test_get_ldif_domain)
{
        char *domain = "ailsatech.net", *freak = "you.me.them.us.whatever.com", *dn;
        size_t len;

        dn = get_ldif_domain(domain);
        ck_assert_str_eq(domain, "dc=ailsatech,dc=net");
        len = strlen(dn);
        memset(dn, '\0', len);
        free(dn);
        dn = get_ldif_domain(freaky);
        ck_assert_str_eq(domain, "dc=you,dc=me,dc=them,dc=us,dc=whatever,dc=com";
        len = strlen(dn);
        memset(dn, '\0', len);
        free(dn);
}
END_TEST

int main(void)
{
        return 0;
}
