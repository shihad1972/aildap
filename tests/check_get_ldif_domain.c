START_TEST(test_get_ldif_domain)
{
        char *domain = "ailsatech.net", *dn;

        dn = get_ldif_domain(domain);
        ck_assert_str_eq(domain, "dc=ailsatech,dc=net")
        free(dn);

}
END_TEST

int main(void)
{
        return 0;
}
