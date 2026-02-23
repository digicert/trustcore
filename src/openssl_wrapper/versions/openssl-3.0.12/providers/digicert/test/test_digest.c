/**
 * test_digest.c
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
#include "../../crypto/md4.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/sha3.h"
#include "../../crypto/blake2.h"

#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/rsa.h"

#include <stdio.h>

int test_digest(OSSL_LIB_CTX *pLibCtx, ubyte hashType)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MD_CTX *pMdCtx;
    EVP_MD *pMd = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    unsigned char hash[140];
    uint8_t hash2[140];
    unsigned int s = 0;
    int cmp = 1;
    char *pAlgoStr = NULL;
    unsigned int digestLen = 0;
    /* for shake */
    OSSL_PARAM params[] = {{"xoflen", OSSL_PARAM_INTEGER, (int *) &digestLen, sizeof(int)},
                           {    NULL,                  0,       NULL,           0}}; 

    switch(hashType)
    {
        case ht_md4:
            pAlgoStr = "MD4";
            digestLen = MD4_RESULT_SIZE;
            break;

        case ht_md5:
            pAlgoStr = "MD5";
            digestLen = MD5_RESULT_SIZE;
            break;

        case ht_sha1:
            pAlgoStr = "SHA-1";
            digestLen = SHA1_RESULT_SIZE;
            break;

        case ht_sha224:
            pAlgoStr = "SHA-224";
            digestLen = SHA224_RESULT_SIZE;
            break;

        case ht_sha256:
            pAlgoStr = "SHA-256";
            digestLen = SHA256_RESULT_SIZE;
            break;

        case ht_sha384:
            pAlgoStr = "SHA-384";
            digestLen = SHA384_RESULT_SIZE;
            break;

        case ht_sha512:
            pAlgoStr = "SHA-512";
            digestLen = SHA512_RESULT_SIZE;
            break;

        case ht_sha3_224:
            pAlgoStr = "SHA3-224";
            digestLen = SHA3_224_RESULT_SIZE;
            break;

        case ht_sha3_256:
            pAlgoStr = "SHA3-256";
            digestLen = SHA3_256_RESULT_SIZE;
            break;
            
        case ht_sha3_384:
            pAlgoStr = "SHA3-384";
            digestLen = SHA3_384_RESULT_SIZE;
            break;

        case ht_sha3_512:
            pAlgoStr = "SHA3-512";
            digestLen = SHA3_512_RESULT_SIZE;
            break;

        case ht_shake128:
            pAlgoStr = "SHAKE-128";
            digestLen = 140; /* test large output */
            break;
    
        case ht_shake256:
            pAlgoStr = "SHAKE-256";
            digestLen = 140;
            break;

        case ht_blake2b:
            pAlgoStr = "BLAKE2B-512";
            digestLen = MOC_BLAKE2B_MAX_OUTLEN;
            break;

        case ht_blake2s:
            pAlgoStr = "BLAKE2S-256";
            digestLen = MOC_BLAKE2S_MAX_OUTLEN;
            break;

        default:
            goto exit;
    }

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;

    pMd = EVP_MD_fetch(pLibCtx, pAlgoStr, NULL);
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (1 == EVP_default_properties_is_fips_enabled(NULL))
    {
        switch (hashType)
        {
            case ht_md4:
                if (NULL != pMd)
                {
                    printf("ERROR EVP_MD_fetch FIPS expected failure\n");
                }
                else
                {
                    status = OK;
                }
                goto exit;
        }
    }
#endif
    if (pMd == NULL)
    {
        printf("ERROR fetching MD\n");
        goto exit;
    }

    if (EVP_DigestInit_ex(pMdCtx, pMd, NULL) != 1)
        goto exit;

    if (ht_shake128 == hashType || ht_shake256 == hashType)
    {
        if (EVP_MD_CTX_set_params(pMdCtx, params) != 1)
            goto exit;
    }

    if (EVP_DigestUpdate(pMdCtx, (const void *)pData, dataLen) != 1)
        goto exit;

    if (EVP_DigestFinal(pMdCtx, (unsigned char *)hash, &s) != 1)
        goto exit;

    if (s != digestLen)
    {
        status = ERR_CMP;
        printf("ERROR hash output lengths differ!, s: %d dlen: %d\n", s, digestLen);
        goto exit;
    }

    /* compute the hash directly and compare */

    switch(hashType)
    {
        case ht_md4:
            status = MD4_completeDigest(pData, (ubyte4) dataLen, (ubyte *) hash2);
            break;
            
        case ht_md5:
            status = MD5_completeDigest(pData, (ubyte4) dataLen, (ubyte *) hash2);
            break;

        case ht_sha1:
            status = SHA1_completeDigest(pData, (ubyte4) dataLen, (ubyte *) hash2);
            break;

        case ht_sha224:
            status = SHA224_completeDigest(pData, (ubyte4) dataLen, (ubyte *) hash2);
            break;

        case ht_sha256:
            status = SHA256_completeDigest(pData, (ubyte4) dataLen, (ubyte *) hash2);
            break;

        case ht_sha384:
            status = SHA384_completeDigest(pData, (ubyte4) dataLen, (ubyte *) hash2);
            break;

        case ht_sha512:
            status = SHA512_completeDigest(pData, (ubyte4) dataLen, (ubyte *) hash2);
            break;

        case ht_sha3_224:
            status = SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_224, pData, (ubyte4) dataLen, (ubyte *) hash2, 0);
            break;

        case ht_sha3_256:
            status = SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_256, pData, (ubyte4) dataLen, (ubyte *) hash2, 0);
            break;

        case ht_sha3_384:
            status = SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_384, pData, (ubyte4) dataLen, (ubyte *) hash2, 0);
            break;

        case ht_sha3_512:
            status = SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_512, pData, (ubyte4) dataLen, (ubyte *) hash2, 0);
            break;

        case ht_shake128:
            status = SHA3_completeDigest(MOCANA_SHA3_MODE_SHAKE128, pData, (ubyte4) dataLen, (ubyte *) hash2, digestLen);
            break;

        case ht_shake256:
            status = SHA3_completeDigest(MOCANA_SHA3_MODE_SHAKE256, pData, (ubyte4) dataLen, (ubyte *) hash2, digestLen);
            break;

        case ht_blake2s:
            status = BLAKE2S_complete(NULL, 0, pData, (ubyte4) dataLen, (ubyte *) hash2, digestLen);
            break;

        case ht_blake2b:
            status = BLAKE2B_complete(NULL, 0, pData, (ubyte4) dataLen, (ubyte *) hash2, digestLen);
            break;

        default:
            goto exit;
    }
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP((ubyte *)hash, hash2, digestLen, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        status = ERR_CMP;
        printf("ERROR hash output does not match!\n");
    }

    status = OK;

exit:

    if (NULL != pMd)
    {
        EVP_MD_free(pMd);
    }
    if (NULL != pMdCtx)
    {
        EVP_MD_CTX_free(pMdCtx);
    }

    return OK == status ? 0 : 1;
}
#endif
