/*
 * moc_evp_copy_test.c
 *
 * Test for EVP copy functions
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

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>

#ifdef __RTOS_WIN32__
#if defined(_MSC_VER) && _MSC_VER < 1900
#define __func__ __FUNCTION__
#endif
#endif

static int test_digest(const EVP_MD *pDigest)
{
    int retVal = 0;
    static int hint = 0;
    EVP_MD_CTX *pCtx = NULL, *pCtxCopy = NULL;
    unsigned char pOut[256] = { 0 };
    unsigned char pOutCopy[256] = { 0 };
    unsigned int outLen = 0, outCopyLen = 0;

    pCtx = EVP_MD_CTX_create();
    if (NULL == pCtx)
    {
        retVal = 1;
        goto exit;
    }

    pCtxCopy = EVP_MD_CTX_create();
    if (NULL == pCtxCopy)
    {
        retVal = 1;
        goto exit;
    }

    if (1 != EVP_DigestInit_ex(pCtx, pDigest, NULL))
    {
        retVal = 1;
        goto exit;
    }

    if (1 != EVP_DigestUpdate(pCtx, "waddup", 6))
    {
        retVal = 1;
        goto exit;
    }

    if (1 != EVP_MD_CTX_copy_ex(pCtxCopy, pCtx))
    {
        retVal = 1;
        goto exit;
    }

    if (1 != EVP_DigestFinal_ex(pCtx, pOut, &outLen))
    {
        retVal = 1;
        goto exit;
    }

    EVP_MD_CTX_destroy(pCtx);
    pCtx = NULL;

    if (1 != EVP_DigestFinal_ex(pCtxCopy, pOutCopy, &outCopyLen))
    {
        retVal = 1;
        goto exit;
    }

    EVP_MD_CTX_destroy(pCtxCopy);
    pCtxCopy = NULL;

    if (outLen != outCopyLen)
    {
        retVal = 1;
        goto exit;
    }

    if (0 != memcmp(pOut, pOutCopy, outLen))
    {
        retVal = 1;
        goto exit;
    }

exit:
    if (pCtxCopy)
    {
        EVP_MD_CTX_destroy(pCtxCopy);
    }

    if (pCtx)
    {
        EVP_MD_CTX_destroy(pCtx);
    }

    if (0 != retVal)
    {
        fprintf(
            stderr, "Error occured on in function %s on test %d\n", __func__, hint);
    }

    hint++;
    return retVal;
}

static int evp_test_copy_digest()
{
    int retVal = 0, i;
    const EVP_MD *pDigests[] = {
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
        EVP_md4(),
#endif
        EVP_md5(),
        EVP_sha1(),
        EVP_sha224(),
        EVP_sha256(),
        EVP_sha384(),
        EVP_sha512()
    };

    for (i = 0; i < sizeof(pDigests)/sizeof(pDigests[0]); i++)
    {
        retVal += test_digest(pDigests[i]);
    }

    return retVal;
}

static int test_cipher(const EVP_CIPHER *pCipher)
{
    int retVal = 0;
    static int hint = 0;
    EVP_CIPHER_CTX *pCtx = NULL, *pCtxCopy = NULL;
    unsigned char *pKey = NULL, *pIv = NULL;
    int keyLen = 0, ivLen = 0, i;
    unsigned char pData[16] = { 0 };
    unsigned char pOut[100] = { 0 };
    unsigned char pOutCopy[100] = { 0 };
    int outLen = 0, outLenCopy = 0;
    int outLenTotal = 0, outLenTotalCopy = 0;

    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        retVal = 1;
        goto exit;
    }

    pCtxCopy = EVP_CIPHER_CTX_new();
    if (NULL == pCtxCopy)
    {
        retVal = 1;
        goto exit;
    }

    keyLen = EVP_CIPHER_key_length(pCipher);
    ivLen = EVP_CIPHER_iv_length(pCipher);

    if (keyLen)
    {
        pKey = OPENSSL_malloc(keyLen);
        for (i = 0; i < keyLen; i++)
        {
            pKey[i] = i;
        }
    }

    if (ivLen)
    {
        pIv = OPENSSL_malloc(ivLen);
        for (i = 0; i < ivLen; i++)
        {
            pIv[i] = i;
        }
    }

    if (1 != EVP_CipherInit_ex(pCtx, pCipher, NULL, pKey, pIv, 1))
    {
        retVal = 1;
        goto exit;
    }

    if (1 != EVP_CipherUpdate(pCtx, pOut, &outLen, pData, sizeof(pData)))
    {
        retVal = 1;
        goto exit;
    }

    outLenTotal += outLen;
    outLenCopy = outLen;
    outLenTotalCopy += outLenCopy;

    if (outLen)
    {
        memcpy(pOutCopy, pOut, outLen);
    }

    if (1 != EVP_CIPHER_CTX_copy(pCtxCopy, pCtx))
    {
        retVal = 1;
        goto exit;
    }

    if (1 != EVP_CipherFinal_ex(pCtx, pOut + outLen, &outLen))
    {
        retVal = 1;
        goto exit;
    }

    outLenTotal += outLen;

    EVP_CIPHER_CTX_free(pCtx);
    pCtx = NULL;

    if (1 != EVP_CipherFinal_ex(pCtxCopy, pOutCopy + outLenCopy, &outLenCopy))
    {
        retVal = 1;
        goto exit;
    }

    outLenTotalCopy += outLenCopy;

    EVP_CIPHER_CTX_free(pCtxCopy);
    pCtxCopy = NULL;

    if (!outLenTotal)
    {
        retVal = 1;
        goto exit;
    }

    if (outLenTotalCopy != outLenTotal)
    {
        retVal = 1;
        goto exit;
    }

    if (0 != memcmp(pOutCopy, pOut, outLenTotal))
    {
        retVal = 1;
        goto exit;
    }

#if 0
    printf("hint %5dX: ", EVP_CIPHER_nid(pCipher));
    for (i = 0; i < outLenTotal; i++)
    {
        printf("%02X ", pOut[i]);
    }
    printf("\n");
#endif

exit:
    if (pCtxCopy)
    {
        EVP_CIPHER_CTX_free(pCtxCopy);
    }

    if (pCtx)
    {
        EVP_CIPHER_CTX_free(pCtx);
    }

    if (pKey)
    {
        OPENSSL_free(pKey);
    }

    if (pIv)
    {
        OPENSSL_free(pIv);
    }

    if (0 != retVal)
    {
        fprintf(
            stderr, "Error occured on in function %s on test %d\n", __func__, hint);
    }

    hint++;
    return retVal;
}

static int evp_test_copy_cipher()
{
    int retVal = 0, i;
    const EVP_CIPHER *pCiphers[] = {
        EVP_aes_128_ecb(),
        EVP_aes_128_cbc(),
        // EVP_aes_128_ofb128(),
        EVP_aes_128_cfb128(),
        EVP_aes_128_ctr(),
        EVP_aes_192_ctr(),
        EVP_aes_256_ctr(),
        EVP_aes_192_ecb(),
        EVP_aes_192_cbc(),
        // EVP_aes_192_ofb128(),
        EVP_aes_192_cfb128(),
        EVP_aes_256_ecb(),
        EVP_aes_256_cbc(),
        // EVP_aes_256_ofb128(),
        EVP_aes_256_cfb128(),
        EVP_aes_128_gcm(),
        EVP_aes_192_gcm(),
        EVP_aes_256_gcm(),
        EVP_aes_256_ccm(),
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
        EVP_aes_128_xts(),
        EVP_aes_256_xts(),
#endif
        EVP_des_ede3_ecb(),
        EVP_des_ede3_cbc(),
        EVP_des_cbc(),
        EVP_des_ecb(),
        // EVP_rc5_ecb(),
        // EVP_rc5_cbc(),
        EVP_rc4(),
        EVP_rc2_ecb(),
        EVP_rc2_cbc(),
        EVP_rc2_40_cbc(),
        // EVP_chacha20(),
        // EVP_chacha20_poly1305(),
        // EVP_id_aes128_wrap(),
        // EVP_id_aes192_wrap(),
        // EVP_id_aes256_wrap()
    };

    for (i = 0; i < sizeof(pCiphers)/sizeof(pCiphers[0]); i++)
    {
        retVal += test_cipher(pCiphers[i]);
    }

    return retVal;
}

int main()
{
    int retVal = 0;
    ENGINE *pEngine = NULL;

    retVal += evp_test_copy_digest();
    retVal += evp_test_copy_cipher();

    FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
    ENGINE_load_builtin_engines();

    pEngine = ENGINE_by_id("mocana");
    if (pEngine == NULL)
    {
        fprintf(stderr, "Mocana Test: Failed to load Mocana Engine\n");
    }

    retVal += evp_test_copy_digest();
    retVal += evp_test_copy_cipher();

    if (0 != retVal)
    {
        fprintf(stderr, "EVP Copy test failed!\n");
    }
    else
    {
        fprintf(stdout, "PASS\n");
    }

    ENGINE_free(pEngine);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();

    return retVal;
}
