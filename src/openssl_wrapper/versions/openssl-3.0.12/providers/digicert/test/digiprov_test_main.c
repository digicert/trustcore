/**
 * digiprov_test_main.c
 *
 * Test of the digicert OSSL 3.0 provider
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGI_PROVIDER_TEST__

#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../../crypto_interface/example/crypto_interface_tap_example.h"
#endif

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/obj_mac.h"
#include <stdio.h>

int test_rsa_enc_dec(OSSL_LIB_CTX *pLibCtx, int bits, byteBoolean isOaep);
int test_digest(OSSL_LIB_CTX *pLibCtx, ubyte hashType);
int test_aes(OSSL_LIB_CTX *pLibCtx, char *pAlgoStr);
int test_cipher(OSSL_LIB_CTX *pLibCtx, char *pAlgoStr);
int test_cipher_aead(OSSL_LIB_CTX *pLibCtx, char *pAlgoStr);
int test_rsa_sign(OSSL_LIB_CTX *pLibCtx, int bits, byteBoolean isPss);
int test_rsa_sign_pem(OSSL_LIB_CTX *pLibCtx, char *pPemFile, byteBoolean isPss);
int test_rsa_enc_dec_pem(OSSL_LIB_CTX *pLibCtx, char *pPemFile, char *pw);
int test_ecdsa_sign(OSSL_LIB_CTX *pLibCtx, int curveBits, const char *pDigest);
int test_ecdsa_sign_pem(OSSL_LIB_CTX *pLibCtx, char *pPemFile);
int test_eddsa_sign(OSSL_LIB_CTX *pLibCtx, const char *pCurve);
int test_dh(OSSL_LIB_CTX *pLibCtx, const char *pCipher, int curve, int group);
int test_dsa_sign(OSSL_LIB_CTX *pLibCtx, int pbits, int qbits, const char *pDigest);
int test_rand(OSSL_LIB_CTX *pLibCtx, const char *pRng, const char *pCipherOrDigest);
int test_mac(OSSL_LIB_CTX *pLibCtx, char *pAlg, char *pDigest);
int test_nist_kdf(OSSL_LIB_CTX *pLibCtx, char *pMode, char *pMac, char *pDigest);
int test_hmac_kdf(OSSL_LIB_CTX *pLibCtx, char *pMode, char *pDigest, ubyte4 digestOutLen);
int test_x963_kdf(OSSL_LIB_CTX *pLibCtx, char *pDigest);
#ifdef __ENABLE_DIGICERT_PQC__
int test_pqc_sign(OSSL_LIB_CTX *pLibCtx, const char *pAlg, const char *pDigest);
int test_pqc_kem(OSSL_LIB_CTX *pLibCtx, const char *pAlg);
#endif
static char *gpPW = NULL;

int my_pem_password_cb(char *buf, int size, int rwflag, void *userdata)
{
    int pwLen = 0;

    if (NULL == gpPW)
        return -1;

    pwLen = (int) DIGI_STRLEN((const sbyte *) gpPW);
    if (size < pwLen)
        return -1;

    (void) DIGI_MEMCPY(buf, gpPW, pwLen);
    return pwLen;
}

int main(int argc, char *argv[])
{
    int ret = 0, tret = 0;
    OSSL_LIB_CTX *pLibCtx = NULL;
    MSTATUS status = OK;
    ubyte4 modNum = 1;
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    int fipsRun = 0;
#endif

#ifdef __LOAD_DEFAULT_PROVIDER__
    OSSL_PROVIDER *pDefault = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *pLegacy = OSSL_PROVIDER_load(NULL, "legacy");
#endif

    if (2 <= argc && ((0 == DIGI_STRCMP((const sbyte *) "help", (const sbyte *) argv[1])) ||
                      (0 == DIGI_STRCMP((const sbyte *) "-help", (const sbyte *) argv[1])) ||
                      (0 == DIGI_STRCMP((const sbyte *) "--help", (const sbyte *) argv[1])) ||
                      (0 == DIGI_STRCMP((const sbyte *) "-h", (const sbyte *) argv[1])) ||
                      (0 == DIGI_STRCMP((const sbyte *) "--h", (const sbyte *) argv[1]))))

    {
        printf("Usage: ./digiprov_test <algorithm group> <key file> <password>\n");
        printf("   All arguments are optional. If omitted all algorithms will be run with\n");
        printf("   internally generated keys. To run a specific group of algorithms use\n");
        printf("   <algorithm group> as one of digest, mac, kdf, cipher, rsa, ecdsa, eddsa, dsa, dh, ecdh, rand\n");
        printf("   If running ecdsa or rsa only, you may use a previously existing key by adding the\n");
        printf("   <key file> as the next argument and if it has a password it can be added after the key file\n.");
        return 0;
    }

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
test_start:
#endif

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "digest", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_digest(pLibCtx, ht_md4);
        ret += test_digest(pLibCtx, ht_md5);
        ret += test_digest(pLibCtx, ht_sha1);
        ret += test_digest(pLibCtx, ht_sha224);
        ret += test_digest(pLibCtx, ht_sha256);
        ret += test_digest(pLibCtx, ht_sha384);
        ret += test_digest(pLibCtx, ht_sha512);
        ret += test_digest(pLibCtx, ht_sha3_224);
        ret += test_digest(pLibCtx, ht_sha3_256);
        ret += test_digest(pLibCtx, ht_sha3_384);
        ret += test_digest(pLibCtx, ht_sha3_512);
        ret += test_digest(pLibCtx, ht_shake128);
        ret += test_digest(pLibCtx, ht_shake256);
        ret += test_digest(pLibCtx, ht_blake2s);
        ret += test_digest(pLibCtx, ht_blake2b);
        
        if (tret == ret)
        {
            printf("digest tests: PASS\n");
        }
        else
        {
            printf("digest tests: FAIL\n");
        }
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "mac", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_mac(pLibCtx, "HMAC", "MD4");
        ret += test_mac(pLibCtx, "HMAC", "MD5");
        ret += test_mac(pLibCtx, "HMAC", "SHA-1");
        ret += test_mac(pLibCtx, "HMAC", "SHA-224");
        ret += test_mac(pLibCtx, "HMAC", "SHA-256");
        ret += test_mac(pLibCtx, "HMAC", "SHA-384");
        ret += test_mac(pLibCtx, "HMAC", "SHA-512");
        ret += test_mac(pLibCtx, "HMAC", "SHA3-224");
        ret += test_mac(pLibCtx, "HMAC", "SHA3-256");
        ret += test_mac(pLibCtx, "HMAC", "SHA3-384");
        ret += test_mac(pLibCtx, "HMAC", "SHA3-512");

        ret += test_mac(pLibCtx, "CMAC", NULL);
        ret += test_mac(pLibCtx, "BLAKE2BMAC", NULL);
        ret += test_mac(pLibCtx, "BLAKE2SMAC", NULL);
        ret += test_mac(pLibCtx, "POLY1305", NULL);

        if (tret == ret)
        {
            printf("mac tests: PASS\n");
        }
        else
        {
            printf("mac tests: FAIL\n");
        }
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "kdf", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "MD4");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "MD5");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA-1");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA-224");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA-256");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA-384");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA-512");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA3-224");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA3-256");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA3-384");
        ret += test_nist_kdf(pLibCtx, "counter", "HMAC", "SHA3-512");

        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "MD4");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "MD5");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA-1");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA-224");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA-256");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA-384");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA-512");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA3-224");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA3-256");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA3-384");
        ret += test_nist_kdf(pLibCtx, "feedback", "HMAC", "SHA3-512");

        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "MD4");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "MD5");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA-1");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA-224");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA-256");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA-384");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA-512");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA3-224");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA3-256");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA3-384");
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "HMAC", "SHA3-512");

        ret += test_nist_kdf(pLibCtx, "counter", "CMAC", NULL);
        ret += test_nist_kdf(pLibCtx, "feedback", "CMAC", NULL);
        ret += test_nist_kdf(pLibCtx, "double-pipeline", "CMAC", NULL);

        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "MD4", 16);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "MD5", 16);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA-1", 20);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA-224", 28);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA-256", 32);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA-384", 48);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA-512", 64);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA3-224", 28);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA3-256", 32);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA3-384", 48);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_AND_EXPAND", "SHA3-512", 64);

        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "MD4", 16);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "MD5", 16);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA-1", 20);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA-224", 28);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA-256", 32);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA-384", 48);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA-512", 64);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA3-224", 28);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA3-256", 32);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA3-384", 48);
        ret += test_hmac_kdf(pLibCtx, "EXTRACT_ONLY", "SHA3-512", 64);

        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "MD4", 16);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "MD5", 16);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA-1", 20);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA-224", 28);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA-256", 32);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA-384", 48);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA-512", 64);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA3-224", 28);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA3-256", 32);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA3-384", 48);
        ret += test_hmac_kdf(pLibCtx, "EXPAND_ONLY", "SHA3-512", 64);

        ret += test_x963_kdf(pLibCtx,"MD4");
        ret += test_x963_kdf(pLibCtx,"MD5");
        ret += test_x963_kdf(pLibCtx,"SHA-1");
        ret += test_x963_kdf(pLibCtx,"SHA-224");
        ret += test_x963_kdf(pLibCtx,"SHA-256");
        ret += test_x963_kdf(pLibCtx,"SHA-384");
        ret += test_x963_kdf(pLibCtx,"SHA-512");
        ret += test_x963_kdf(pLibCtx,"SHA3-224");
        ret += test_x963_kdf(pLibCtx,"SHA3-256");
        ret += test_x963_kdf(pLibCtx,"SHA3-384");
        ret += test_x963_kdf(pLibCtx,"SHA3-512");

        if (tret == ret)
        {
            printf("kdf tests: PASS\n");
        }
        else
        {
            printf("kdf tests: FAIL\n");
        }
    }


    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "cipher", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_aes(pLibCtx, "AES-128-CBC");
        ret += test_aes(pLibCtx, "AES-192-CBC");
        ret += test_aes(pLibCtx, "AES-256-CBC");

        ret += test_aes(pLibCtx, "AES-128-ECB");
        ret += test_aes(pLibCtx, "AES-192-ECB");
        ret += test_aes(pLibCtx, "AES-256-ECB");

        ret += test_aes(pLibCtx, "AES-128-OFB");
        ret += test_aes(pLibCtx, "AES-192-OFB");
        ret += test_aes(pLibCtx, "AES-256-OFB");

        ret += test_aes(pLibCtx, "AES-128-CFB");
        ret += test_aes(pLibCtx, "AES-192-CFB");
        ret += test_aes(pLibCtx, "AES-256-CFB");

        ret += test_cipher(pLibCtx, "AES-128-CTR");
        ret += test_cipher(pLibCtx, "AES-192-CTR");
        ret += test_cipher(pLibCtx, "AES-256-CTR");
        ret += test_cipher(pLibCtx, "AES-128-XTS");
        ret += test_cipher(pLibCtx, "AES-256-XTS");

        ret += test_cipher(pLibCtx, "DES-EDE3-ECB");
        ret += test_cipher(pLibCtx, "DES-EDE3-CBC");

        ret += test_cipher(pLibCtx, "DES-ECB");
        ret += test_cipher(pLibCtx, "DES-CBC");

      /*  ret += test_cipher(pLibCtx, "BF-ECB"); not supported */
        ret += test_cipher(pLibCtx, "BF-CBC");

        ret += test_cipher(pLibCtx, "RC5-ECB");
        ret += test_cipher(pLibCtx, "RC5-CBC");

        ret += test_cipher(pLibCtx, "RC4");
        ret += test_cipher(pLibCtx, "RC4-40");

        ret += test_cipher(pLibCtx, "ChaCha20");

        ret += test_cipher_aead(pLibCtx, "AES-128-GCM");
        ret += test_cipher_aead(pLibCtx, "AES-192-GCM");
        ret += test_cipher_aead(pLibCtx, "AES-256-GCM");

        ret += test_cipher_aead(pLibCtx, "AES-128-CCM");
        ret += test_cipher_aead(pLibCtx, "AES-192-CCM");
        ret += test_cipher_aead(pLibCtx, "AES-256-CCM");

        ret += test_cipher_aead(pLibCtx, "ChaCha20-Poly1305");

        if (tret == ret)
        {
            printf("cipher tests: PASS\n");
        }
        else
        {
            printf("cipher tests: FAIL\n");
        }
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "rsa", (const sbyte *) argv[1]))
    {
        char *pw = NULL;
        
        tret = ret;
        ret += test_rsa_sign(pLibCtx, 1024, FALSE);
        ret += test_rsa_sign(pLibCtx, 1024, TRUE);
        ret += test_rsa_sign(pLibCtx, 2048, FALSE);
        ret += test_rsa_sign(pLibCtx, 2048, TRUE);

        if (3 <= argc)
        {
            if (4 <= argc)
            {
                gpPW = (char *) argv[3];
            }
                        
            /* we init TAP after already using the provider, ie so DIGICERT_initialize has been called */
#ifdef __ENABLE_DIGICERT_TAP__ 
            status = TAP_EXAMPLE_init(&modNum,1);
            if (OK != status)
            {
                ret = 1;
                goto exit;
            }
#endif
            ret += test_rsa_sign_pem(pLibCtx, argv[2], FALSE);
            ret += test_rsa_sign_pem(pLibCtx, argv[2], TRUE);
        }

#ifdef __ENABLE_RSA_LARGE_KEYSIZE_TESTS__
        ret += test_rsa_sign(pLibCtx, 3072, FALSE);
        ret += test_rsa_sign(pLibCtx, 3072, TRUE);
        ret += test_rsa_sign(pLibCtx, 4096, FALSE);
        ret += test_rsa_sign(pLibCtx, 4096, TRUE);
        ret += test_rsa_sign(pLibCtx, 8192, FALSE);
        ret += test_rsa_sign(pLibCtx, 8192, TRUE);
#endif
        ret += test_rsa_enc_dec(pLibCtx, 1024, FALSE);
        ret += test_rsa_enc_dec(pLibCtx, 1024, TRUE);
        ret += test_rsa_enc_dec(pLibCtx, 2048, FALSE);
        ret += test_rsa_enc_dec(pLibCtx, 2048, TRUE);

        if (3 <= argc)
        {
            ret += test_rsa_enc_dec_pem(pLibCtx, argv[2], gpPW);
        }

#ifdef __ENABLE_RSA_LARGE_KEYSIZE_TESTS__
        ret += test_rsa_enc_dec(pLibCtx, 3072, FALSE);
        ret += test_rsa_enc_dec(pLibCtx, 3072, TRUE);
        ret += test_rsa_enc_dec(pLibCtx, 4096, FALSE);
        ret += test_rsa_enc_dec(pLibCtx, 4096, TRUE);
        ret += test_rsa_enc_dec(pLibCtx, 8192, FALSE);
        ret += test_rsa_enc_dec(pLibCtx, 8192, TRUE);
#endif
        if (tret == ret)
        {
            printf("rsa tests: PASS\n");
        }
        else
        {
            printf("rsa tests: FAIL\n");
        }
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "ecdsa", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_ecdsa_sign(pLibCtx, NID_X9_62_prime192v1, "SHA-1");
        ret += test_ecdsa_sign(pLibCtx, NID_secp224r1, "SHA-224");
        ret += test_ecdsa_sign(pLibCtx, NID_X9_62_prime256v1, "SHA-256");
        ret += test_ecdsa_sign(pLibCtx, NID_secp384r1, "SHA-384");
        ret += test_ecdsa_sign(pLibCtx, NID_secp521r1, "SHA-512");

        if (3 <= argc)
        {
            char *pw = NULL;

            if (4 <= argc)
            {
                gpPW = (char *) argv[3];
            }

            /* we init TAP after already using the provider, ie so DIGICERT_initialize has been called */
#ifdef __ENABLE_DIGICERT_TAP__ 
            status = TAP_EXAMPLE_init(&modNum,1);
            if (OK != status)
            {
                ret = 1;
                goto exit;
            }
#endif
            ret += test_ecdsa_sign_pem(pLibCtx, argv[2]);
        }

        if (tret == ret)
        {
            printf("ecdsa tests: PASS\n");
        }
        else
        {
            printf("ecdsa tests: FAIL\n");
        }
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "eddsa", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_eddsa_sign(pLibCtx, "ED25519");
        ret += test_eddsa_sign(pLibCtx, "ED448");

        if (tret == ret)
        {
            printf("eddsa tests: PASS\n");
        }
        else
        {
            printf("eddsa tests: FAIL\n");
        }
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "dsa", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_dsa_sign(pLibCtx, 1024, 160, "SHA-1");
        ret += test_dsa_sign(pLibCtx, 2048, 224, "SHA-224");
        ret += test_dsa_sign(pLibCtx, 2048, 256, "SHA-256");
     /* ret += test_dsa_sign(pLibCtx, 3072, 384, "SHA-384");
        ret += test_dsa_sign(pLibCtx, 4096, 512, "SHA-512"); not supported */

        if (tret == ret)
        {
            printf("dsa tests: PASS\n");
        }
        else
        {
            printf("dsa tests: FAIL\n");
        }
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "dh", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_dh(pLibCtx, "DH", 0, NID_ffdhe2048);
        ret += test_dh(pLibCtx, "DH", 0, NID_ffdhe3072);
        ret += test_dh(pLibCtx, "DH", 0, NID_ffdhe4096);
        ret += test_dh(pLibCtx, "DH", 0, NID_ffdhe6144);
        ret += test_dh(pLibCtx, "DH", 0, NID_ffdhe8192);
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
        ret += test_dh(pLibCtx, "DH", 0, NID_modp_1536);
#endif
        ret += test_dh(pLibCtx, "DH", 0, NID_modp_2048);
        ret += test_dh(pLibCtx, "DH", 0, NID_modp_3072);
        ret += test_dh(pLibCtx, "DH", 0, NID_modp_4096);
        ret += test_dh(pLibCtx, "DH", 0, NID_modp_6144);
        ret += test_dh(pLibCtx, "DH", 0, NID_modp_8192);

        if (tret == ret)
        {
            printf("dh tests: PASS\n");
        }
        else
        {
            printf("dh tests: FAIL\n");
        }  
    }

    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "ecdh", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_dh(pLibCtx, "EC", NID_X9_62_prime192v1, 0);
        ret += test_dh(pLibCtx, "EC", NID_secp224r1, 0);
        ret += test_dh(pLibCtx, "EC", NID_X9_62_prime256v1, 0);
        ret += test_dh(pLibCtx, "EC", NID_secp384r1, 0);
        ret += test_dh(pLibCtx, "EC", NID_secp521r1, 0);
        ret += test_dh(pLibCtx, "X25519", 0, 0);
        ret += test_dh(pLibCtx, "X448", 0, 0);

        if (tret == ret)
        {
            printf("ecdh tests: PASS\n");
        }
        else
        {
            printf("ecdh tests: FAIL\n");
        }
    }
    
    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "rand", (const sbyte *) argv[1]))
    {
        tret = ret;
        ret += test_rand(pLibCtx, "CTR-DRBG", "AES-128-CTR");
        ret += test_rand(pLibCtx, "CTR-DRBG", "AES-192-CTR");
        ret += test_rand(pLibCtx, "CTR-DRBG", "AES-256-CTR");
        ret += test_rand(pLibCtx, "CTR-DRBG", "TDES-CTR");

        /* HASH-DRBG with MD4, and MD5 not supported as per RFC */
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA-1");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA-224");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA-256");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA-384");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA-512");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA3-224");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA3-256");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA3-384");
        ret += test_rand(pLibCtx, "HASH-DRBG", "SHA3-512");

        if (tret == ret)
        {
            printf("rand tests: PASS\n");
        }
        else
        {
            printf("rand tests: FAIL\n");
        }
    }

#ifdef __ENABLE_DIGICERT_PQC__
    if (1 == argc || 0 == DIGI_STRCMP((const sbyte *) "pqc", (const sbyte *) argv[1]))
    {
        tret = ret;
        
        ret += test_pqc_kem(pLibCtx, "ML-KEM-512");
        ret += test_pqc_kem(pLibCtx, "ML-KEM-768");
        ret += test_pqc_kem(pLibCtx, "ML-KEM-1024");

        ret += test_pqc_sign(pLibCtx, "ML-DSA-44", NULL);
        ret += test_pqc_sign(pLibCtx, "ML-DSA-65", NULL);
        ret += test_pqc_sign(pLibCtx, "ML-DSA-87", NULL);

        ret += test_pqc_sign(pLibCtx, "ML-DSA-44", "SHA-256");
        ret += test_pqc_sign(pLibCtx, "ML-DSA-44", "SHA-512");
        ret += test_pqc_sign(pLibCtx, "ML-DSA-44", "SHAKE-128");

        ret += test_pqc_sign(pLibCtx, "ML-DSA-65", "SHA-512");
        ret += test_pqc_sign(pLibCtx, "ML-DSA-87", "SHA-512");
 
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-128F", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-128S", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-192F", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-192S", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-256F", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-256S", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-128F", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-128S", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-192F", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-192S", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-256F", NULL);
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-256S", NULL);

/*      Uncomment once SLH-DSA has signDigest and verifyDigest APIs  
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-128F", "SHA-256");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-128S", "SHA-256");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-192F", "SHA-512");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-192S", "SHA-512");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-256F", "SHA-512");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHA2-256S", "SHA-512");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-128F", "SHAKE-128");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-128S", "SHAKE-128");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-192F", "SHAKE-256");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-192S", "SHAKE-256");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-256F", "SHAKE-256");
        ret += test_pqc_sign(pLibCtx, "SLH-DSA-SHAKE-256S", "SHAKE-256"); */

        if (tret == ret)
        {
            printf("pqc tests: PASS\n");
        }
        else
        {
            printf("pqc tests: FAIL\n");
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (0 == fipsRun)
    {
        fipsRun = 1;
        EVP_set_default_properties(NULL, "fips=yes");
        goto test_start;
    }
#endif

    printf("Test end, ret: %d\n", ret);

exit:

#ifdef __ENABLE_DIGICERT_TAP__
    TAP_EXAMPLE_clean();
#endif

    if (NULL != pLibCtx)
        OSSL_LIB_CTX_free(pLibCtx);

#ifdef __LOAD_DEFAULT_PROVIDER__
    if (NULL != pDefault)
        OSSL_PROVIDER_unload(pDefault);
    if (NULL != pLegacy)
        OSSL_PROVIDER_unload(pLegacy);
#endif

    printf("end main\n");
    return 0;
}
#endif
