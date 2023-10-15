#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "../include/ailsaldap.h"

START_TEST(check_kv_init)
{
        ailsa_kv_s *kv = NULL;

        init_kv_s(&kv);
        ck_assert_ptr_nonnull(kv);
        clean_kv_s(&kv);
}
END_TEST

START_TEST(check_kv_object)
{
        ailsa_kv_s *kv = NULL;
        const char *key = "format";
        const char *value = "stable";
        init_kv_s(&kv);
        ck_assert_ptr_nonnull(kv);
        put_kv_key(kv, key);
        put_kv_value(kv, value);
        ck_assert_ptr_nonnull(get_kv_key(kv));
        ck_assert_ptr_nonnull(get_kv_value(kv));
        ck_assert_str_eq(get_kv_key(kv), key);
        ck_assert_str_eq(get_kv_value(kv), value);
        clean_kv_s(&kv);
}
END_TEST

Suite * kv_suite(void)
{
        Suite *s;
        TCase *ailsa;
        s = suite_create("kv");
        ailsa = tcase_create("kv_core");
        tcase_add_test(ailsa, check_kv_init);
        tcase_add_test(ailsa, check_kv_object);
        suite_add_tcase(s, ailsa);

        return s;
}

int
main(void)
{
        int failed = 0;
        Suite *s;
        SRunner *sr;
 
        s = kv_suite();
        sr = srunner_create(s);

        srunner_run_all(sr, CK_ENV);
        failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
