#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "../include/ailsaldap.h"
START_TEST(check_dn_ailsatech)
{
        const char *domain = "ailsatech.net";
        char *dn;
        size_t len;

        dn = get_ldif_format(domain, "dc", ".");
        ck_assert_str_eq(dn, "dc=ailsatech,dc=net");
        len = strlen(dn);
        memset(dn, '\0', len);
        free(dn);
}
END_TEST

START_TEST(check_dn_freaky)
{
        const char *freaky = "you.me.them.us.whatever.com";
        char *dn;
        size_t len;

        dn = get_ldif_format(freaky, "dc", ".");
        ck_assert_str_eq(dn, "dc=you,dc=me,dc=them,dc=us,dc=whatever,dc=com");
        len = strlen(dn);
        memset(dn, '\0', len);
        free(dn);
}
END_TEST

START_TEST (check_dn_null)
{
        const char *null = '\0';
        char *dn;

        dn = get_ldif_format(null, null, null);
        ck_assert_pstr_eq(dn, null);
}
END_TEST

Suite * get_ldif_format_suite(void)
{
        Suite *s;
        TCase *ailsatech;

        s = suite_create("get_ldif_format");
        ailsatech = tcase_create("Strings");
        tcase_add_test(ailsatech, check_dn_ailsatech);
        tcase_add_test(ailsatech, check_dn_freaky);
        tcase_add_test(ailsatech, check_dn_null);
        suite_add_tcase(s, ailsatech);

        return s;
}

int main(void)
{
        int number_failed;
        Suite *s;
        SRunner *sr;

        s = get_ldif_format_suite();
        sr = srunner_create(s);

        srunner_run_all(sr, CK_ENV);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
