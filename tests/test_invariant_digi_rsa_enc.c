#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>

/*
 * This test verifies the security invariant that RSA OAEP operations
 * must NOT default to SHA-1 when no hash algorithm is explicitly specified.
 * The default should be SHA-256 or stronger per NIST SP 800-131A.
 */

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *digicert_provider = NULL;

static void setup(void)
{
    libctx = OSSL_LIB_CTX_new();
    ck_assert_ptr_nonnull(libctx);
    digicert_provider = OSSL_PROVIDER_load(libctx, "digicert");
    ck_assert_ptr_nonnull(digicert_provider);
}

static void teardown(void)
{
    OSSL_PROVIDER_unload(digicert_provider);
    OSSL_LIB_CTX_free(libctx);
    digicert_provider = NULL;
    libctx = NULL;
}

START_TEST(test_rsa_oaep_default_hash_not_sha1)
{
    /* Invariant: When RSA OAEP is used without specifying a hash,
     * the default MUST NOT be SHA-1 */
    const char *weak_defaults[] = {
        "SHA1",       /* exact exploit: the weak default */
        "SHA-1",      /* boundary: alternate name for SHA-1 */
        "sha1",       /* boundary: case variation */
    };
    const char *acceptable[] = {
        "SHA-256", "SHA-384", "SHA-512", "SHA2-256", "SHA2-384", "SHA2-512"
    };
    const int n_acceptable = (int)(sizeof(acceptable) / sizeof(acceptable[0]));

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *keygen_ctx = NULL;

    /* Generate a test RSA key via the DigiCert provider's libctx */
    keygen_ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    ck_assert_ptr_nonnull(keygen_ctx);
    ck_assert_int_eq(EVP_PKEY_keygen_init(keygen_ctx), 1);
    ck_assert_int_eq(EVP_PKEY_CTX_set_rsa_keygen_bits(keygen_ctx, 2048), 1);
    ck_assert_int_eq(EVP_PKEY_keygen(keygen_ctx, &pkey), 1);
    EVP_PKEY_CTX_free(keygen_ctx);

    /* Create encryption context with OAEP padding, no explicit MD set,
     * anchored to the DigiCert provider's libctx */
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    ck_assert_ptr_nonnull(ctx);
    ck_assert_int_eq(EVP_PKEY_encrypt_init(ctx), 1);
    ck_assert_int_eq(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), 1);

    /* Query the default OAEP MD without setting one explicitly */
    char mdname[64] = {0};
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                         mdname, sizeof(mdname)),
        OSSL_PARAM_construct_end()
    };
    int got_params = EVP_PKEY_CTX_get_params(ctx, params);

    /* A silent pass here would be a false negative — assert both conditions */
    ck_assert_msg(got_params == 1,
        "EVP_PKEY_CTX_get_params() failed to retrieve OAEP digest name");
    ck_assert_msg(mdname[0] != '\0',
        "OAEP digest name is empty — cannot verify the security invariant");

    /* Verify the default is NOT SHA-1 */
    for (int i = 0; i < 3; i++) {
        ck_assert_msg(OPENSSL_strcasecmp(mdname, weak_defaults[i]) != 0,
            "OAEP default hash is SHA-1 ('%s'), which is cryptographically weak",
            mdname);
    }

    /* Verify the default IS an acceptable strong digest (positive allowlist) */
    int found_acceptable = 0;
    for (int i = 0; i < n_acceptable; i++) {
        if (OPENSSL_strcasecmp(mdname, acceptable[i]) == 0) {
            found_acceptable = 1;
            break;
        }
    }
    ck_assert_msg(found_acceptable,
        "OAEP default hash '%s' is not in the acceptable strong digest list "
        "(SHA-256/384/512 family required per NIST SP 800-131A)", mdname);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_rsa_oaep_default_hash_not_sha1);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
