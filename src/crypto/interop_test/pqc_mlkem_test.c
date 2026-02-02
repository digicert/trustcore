/*
 * pqc_mlkem_test.c
 *
 * Interopability test for ML-KEM algorithms.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/initmocana.h"
#include "../../common/random.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/crypto.h"
#include "../../crypto/pqc/mlkem.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../../projects/crypto_interop_test/boringssl/include/openssl/bytestring.h"
#include "../../../projects/crypto_interop_test/boringssl/include/openssl/mlkem.h"

#ifndef PQC_MLKEM_TEST_ITERATIONS
#define PQC_MLKEM_TEST_ITERATIONS 20000
#endif

/* ----------------------------------------------------------------------- */

static int bssl_init_digicert_resp(ubyte4 hint, ubyte4 size)
{
    MSTATUS status = OK;
    int retVal = 0;
    int ret = 0;
    sbyte4 cmp = -1;
    MLKEMCtx ctx = {0};
    MLKEMType type = 0;

    ubyte pSS[32];       /* same for all modes */
    size_t ssLen = 0;

    ubyte pCipher[1568]; /* big enough for both modes */
    size_t cipherLen = 0;

    ubyte pPub[1568];    /* big enough for both modes */
    size_t pubLen = 0;

    uint8_t bsslSS[32];

    struct MLKEM768_private_key private_key_768 = {0};
    struct MLKEM1024_private_key private_key_1024 = {0};

    /* generate a key first with basl */
    if (768 == size)
    {
        MLKEM768_generate_key((uint8_t *) pPub, NULL, &private_key_768);
        pubLen = 1184;
        type = MLKEM_TYPE_768;
    }
    else /* 1024 == size */
    {
        MLKEM1024_generate_key((uint8_t *) pPub, NULL, &private_key_1024);
        pubLen = 1568;
        type = MLKEM_TYPE_1024;
    }

    /* Encapsulate with Digicert */
    status = MLKEM_createCtx(type, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_setPublicKey(pPub, pubLen, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_getCipherTextLen(&ctx, &cipherLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_getSharedSecretLen(&ctx, &ssLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_encapsulate(&ctx, RANDOM_rngFun, g_pRandomContext, pCipher, cipherLen, pSS, ssLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Decapsulate with bssl */
    if (768 == size)
    {
        ret = MLKEM768_decap(bsslSS, (const uint8_t *) pCipher, cipherLen, &private_key_768);
    }
    else
    {
        ret = MLKEM1024_decap(bsslSS, (const uint8_t *) pCipher, cipherLen, &private_key_1024);
    }
    if (1 != ret)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    if (32 != ssLen)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    /* compare secrets */
    status = DIGI_MEMCMP(pSS, (ubyte *) bsslSS, ssLen, &cmp);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    status = MLKEM_destroyCtx(&ctx);
    retVal += UNITTEST_STATUS(hint, status);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int digicert_init_bssl_resp(ubyte4 hint, ubyte4 size)
{
    MSTATUS status = OK;
    int retVal = 0;
    int ret = 0;
    sbyte4 cmp = -1;
    MLKEMCtx ctx = {0};
    MLKEMType type = MLKEM_TYPE_768;
    if (size == 1024) {
        type = MLKEM_TYPE_1024;
    }

    ubyte pSS[32];       /* same for all modes */
    size_t ssLen = 0;

    uint8_t pCipher[1568]; /* big enough for both modes */
    size_t cipherLen = 0;

    ubyte pPub[1568];    /* big enough for both modes */
    size_t pubLen = 0;

    uint8_t bsslSS[32];
    CBS pubCbs;

    struct MLKEM768_public_key public_key_768 = {0};
    struct MLKEM1024_public_key public_key_1024 = {0};

    /* Generate a key with Digicert */
    status = MLKEM_createCtx(type, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_generateKeyPair(RANDOM_rngFun, g_pRandomContext, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_getPublicKeyLen(&ctx, &pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_getPublicKey(&ctx, pPub, pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Encapsulate with bssl */
    CBS_init(&pubCbs, (const uint8_t *) pPub, pubLen);

    if (768 == size)
    {
        cipherLen = MLKEM768_CIPHERTEXT_BYTES;
        ret = MLKEM768_parse_public_key(&public_key_768, &pubCbs);
        if (1 != ret)
        {
            /* remember 1 is success for bssl, force error if not success */
            retVal += UNITTEST_STATUS(hint, -1);
            goto exit;
        }

        MLKEM768_encap(pCipher, bsslSS, &public_key_768);
    }
    else
    {
        cipherLen = MLKEM1024_CIPHERTEXT_BYTES;
        ret = MLKEM1024_parse_public_key(&public_key_1024, &pubCbs);
        if (1 != ret)
        {
            /* remember 1 is success for bssl, force error if not success */
            retVal += UNITTEST_STATUS(hint, -1);
            goto exit;
        }

        MLKEM1024_encap(pCipher, bsslSS, &public_key_1024);
    }

    /* decapsulate with Digicert */
    status = MLKEM_getSharedSecretLen(&ctx, &ssLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_decapsulate(&ctx, pCipher, cipherLen, pSS, ssLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (32 != ssLen)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    /* compare secrets */
    status = DIGI_MEMCMP(pSS, (ubyte *) bsslSS, ssLen, &cmp);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    status = MLKEM_destroyCtx(&ctx);
    retVal += UNITTEST_STATUS(hint, status);

    return retVal;
}

/* ----------------------------------------------------------------------- */

int pqc_mlkem_test_all()
{
    MSTATUS status = OK;
    int retVal = 0;
    int i = 0;
    ubyte4 size = 512;

    status = DIGICERT_initDigicert();
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    for (i = 0; i < PQC_MLKEM_TEST_ITERATIONS; i++)
    {
        /* we'll do 1/3 of the iterations at each mode */
        if (PQC_MLKEM_TEST_ITERATIONS/3 == i)
        {
            size = 768;
        }
        else if (2 * PQC_MLKEM_TEST_ITERATIONS/3 == i)
        {
            size = 1024;
        }

        if (size >= 678)
        {
            retVal += bssl_init_digicert_resp(i, size);
            retVal += digicert_init_bssl_resp(i, size);
        }
    }

exit:

    (void) DIGICERT_freeDigicert();

    return retVal;
}
