/*
 * pqc_mldsa_test.c
 * 
 * Interopability test for ML-DSA algorithms.
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
#include "../../crypto/pqc/mldsa.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../../projects/crypto_interop_test/boringssl/include/openssl/bytestring.h"
#include "../../../projects/crypto_interop_test/boringssl/include/openssl/mldsa.h"

#include "../../../projects/crypto_interop_test/wolfssl/wolfssl/options.h"
#include "../../../projects/crypto_interop_test/wolfssl/wolfssl/wolfcrypt/dilithium.h"

#ifndef PQC_MLDSA_TEST_ITERATIONS
#define PQC_MLDSA_TEST_ITERATIONS 5000
#endif

/* ----------------------------------------------------------------------- */

static int bssl_sign(ubyte4 hint, ubyte *pData, size_t dataLen, ubyte *pCtx, size_t ctxLen,
                     ubyte *pPub, ubyte *pSig)
{
    int retVal = 0;
    int ret = 0;

    uint8_t seed[MLDSA_SEED_BYTES];
    struct MLDSA65_private_key private_key = {0};

    /* generate a key first with basl */
    ret = MLDSA65_generate_key((uint8_t *) pPub, seed, &private_key);
    if (1 != ret)
    {
        /* remember 1 is success for bssl, force error if not success */
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    /* sign with bssl */
    ret = MLDSA65_sign((uint8_t *) pSig, &private_key, (const uint8_t *) pData, dataLen,
                       (const uint8_t *) pCtx, ctxLen);
    if (1 != ret)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int bssl_verify(ubyte4 hint, ubyte *pData, size_t dataLen, ubyte *pCtx, size_t ctxLen,
                       ubyte *pPub, ubyte4 pubLen, ubyte *pSig, size_t sigLen)
{
    int retVal = 0;
    int ret = 0;
    CBS pubCbs;
    struct MLDSA65_public_key public_key = {0};

    CBS_init(&pubCbs, (const uint8_t *) pPub, pubLen);

    ret = MLDSA65_parse_public_key(&public_key, &pubCbs);
    if (1 != ret)
    {
        /* remember 1 is success for bssl, force error if not success */
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    ret = MLDSA65_verify(&public_key, (const uint8_t *) pSig, sigLen, (const uint8_t *) pData, dataLen,
                         (const uint8_t *) pCtx, ctxLen);
    if (1 != ret)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int wolfssl_sign(ubyte4 hint, ubyte mode, ubyte *pData, size_t dataLen,
                        ubyte *pPub, size_t *pPubLen, ubyte *pSig, size_t *pSigLen)
{
    int retVal = 0;
    int ret = 0;
    ubyte pDataCopy[257];

    MlDsaKey private_key = {0};
    WC_RNG rng = {0};

    /* wolfssl doesn't prefix the data with the domain separater and contextLen, we'll manually add */
    pDataCopy[0] = 0; /* zero for non-prehash mode */
    pDataCopy[1] = 0; /* zero context Len */
    (void) DIGI_MEMCPY(pDataCopy + 2, pData, dataLen);
    dataLen += 2;

    ret = wc_InitRng(&rng);
    retVal += UNITTEST_STATUS(hint, ret);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_SetParams(&private_key, mode);
    retVal += UNITTEST_STATUS(hint, ret);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_MakeKey(&private_key, &rng);
    retVal += UNITTEST_STATUS(hint, ret);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_ExportPubRaw(&private_key, pPub, (word32 *) pPubLen);
    retVal += UNITTEST_STATUS(hint, ret);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_Sign(&private_key, pSig, (word32 *) pSigLen, pDataCopy, dataLen, &rng);
    retVal += UNITTEST_STATUS(hint, ret);

exit:

    wc_MlDsaKey_Free(&private_key);
    wc_FreeRng(&rng);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int wolfssl_verify(ubyte4 hint, ubyte mode, ubyte *pData, size_t dataLen,
                          ubyte *pPub, size_t pubLen, ubyte *pSig, size_t sigLen)
{
    int retVal = 0;
    int ret = 0;
    int res = 0; /* 0 is sig fail, 1 is valid */
    ubyte pDataCopy[257];

    MlDsaKey public_key = {0};

    /* wolfssl doesn't prefix the data with the domain separater and contextLen, we'll manually add */
    pDataCopy[0] = 0; /* zero for non-prehash mode */
    pDataCopy[1] = 0; /* zero context Len */
    (void) DIGI_MEMCPY(pDataCopy + 2, pData, dataLen);
    dataLen += 2;

    ret = wc_MlDsaKey_SetParams(&public_key, mode);
    retVal += UNITTEST_STATUS(hint, ret);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_ImportPubRaw(&public_key, pPub, pubLen);
    retVal += UNITTEST_STATUS(hint, ret);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_Verify(&public_key, pSig, sigLen, pDataCopy, dataLen, &res);
    retVal += UNITTEST_STATUS(hint, ret);
    if (0 != ret)
        goto exit;

    if (1 != res)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    wc_MlDsaKey_Free(&public_key);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int digicert_sign(ubyte4 hint, ubyte mode, ubyte *pData, size_t dataLen, ubyte *pCtx, size_t ctxLen,
                         ubyte *pPub, size_t *pPubLen, ubyte *pSig, size_t *pSigLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;

    MLDSACtx ctx = {0};
    size_t sigLen = 0;
    size_t pubLen = 0;

    /* Verify with us */
    status = MLDSA_createCtx(mode, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_getSignatureLen(&ctx, &sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_getPublicKeyLen(&ctx, &pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_generateKeyPair(RANDOM_rngFun, g_pRandomContext, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_getPublicKey(&ctx, pPub, pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_signMessage(&ctx, pData, dataLen, RANDOM_rngFun, g_pRandomContext, pSig, sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    *pSigLen = sigLen;
    *pPubLen = pubLen;

exit:

    status = MLDSA_destroyCtx(&ctx);
    retVal += UNITTEST_STATUS(hint, status);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int digicert_verify(ubyte4 hint, ubyte mode, ubyte *pData, size_t dataLen, ubyte *pCtx, size_t ctxLen,
                           ubyte *pPub, size_t pubLen, ubyte *pSig, size_t sigLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;

    MLDSACtx ctx = {0};

    /* Verify with us */
    status = MLDSA_createCtx(mode, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_setPublicKey(pPub, pubLen, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_verifyMessage(&ctx, pData, dataLen, pSig, sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

exit:

    status = MLDSA_destroyCtx(&ctx);
    retVal += UNITTEST_STATUS(hint, status);

    return retVal;
}

/* ----------------------------------------------------------------------- */

int pqc_mldsa_test_all()
{
    MSTATUS status = OK;
    int retVal = 0;
    int i = 0;
    ubyte mode = MLDSA_TYPE_44;
    ubyte wolfMode = WC_ML_DSA_44;

    ubyte pData[512]; /* space for a message and context */
    size_t dataLen = 0;
    ubyte *pCtx = NULL;
    size_t ctxLen = 0;

    ubyte pPub[2592]; /* big enough for all modes */
    size_t pubLen = 0;

    ubyte pSig[4627]; /* big enough for all modes */
    size_t sigLen = 0;

    status = DIGICERT_initDigicert();
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    for (i = 0; i < PQC_MLDSA_TEST_ITERATIONS; i++)
    {
        /* we'll do 1/3 of the iterations at each mode */
        if (PQC_MLDSA_TEST_ITERATIONS/3 == i)
        {
            mode = MLDSA_TYPE_65;
            wolfMode = WC_ML_DSA_65;
        }
        else if (2 * PQC_MLDSA_TEST_ITERATIONS/3 == i)
        {
            mode = MLDSA_TYPE_87;
            wolfMode = WC_ML_DSA_87;
        }

        /* create a random msg and context, first just fill the buffer  */
        status = (MSTATUS) RANDOM_rngFun(g_pRandomContext, sizeof(pData), pData);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        /* use the last two bytes to pick random lengths from 0 to 255 */
        dataLen = (ubyte4) pData[511];

        /**** BSSL compatibility tests, for 65 only ****/
        if (MLDSA_TYPE_65 == mode)
        {
            /* bssl has context mode, use the second half of the buffer as a random context */
            //ctxLen = (ubyte4) pData[510];
            if (ctxLen)
            {
                pCtx = pData + 255;
            }
            else
            {
                pCtx = NULL;
            }

            /* Digicert Sign with context */
            retVal += digicert_sign(i, mode, pData, dataLen, pCtx, ctxLen, pPub, &pubLen, pSig, &sigLen);

            /* bssl Verify with context */
            retVal += bssl_verify(i, pData, dataLen, pCtx, ctxLen, pPub, pubLen, pSig, sigLen);
            (void) DIGI_MEMSET(pSig, 0x00, sigLen);

            /* bssl Sign with context */
            retVal += bssl_sign(i, pData, dataLen, pCtx, ctxLen, pPub, pSig);
            pubLen = MLDSA65_PUBLIC_KEY_BYTES; /* get lengths from bssl macros */
            sigLen = MLDSA65_SIGNATURE_BYTES;

            /* Digicert Verify with context */
            retVal += digicert_verify(i, mode, pData, dataLen, pCtx, ctxLen, pPub, pubLen, pSig, sigLen);
            (void) DIGI_MEMSET(pSig, 0x00, sigLen);

        }

        /**** WolfSSL compatibility tests, for 44 only  ****/

        /* WOLF incorrectly hashes the first 32 bytes of the seed pho in SampleInBall
           for 44 this is right but for 65 and 87 it should be 48 and 64 bytes resp */
        if (MLDSA_TYPE_44 == mode)
        {
            /* Digicert Sign, no context */
            retVal += digicert_sign(i, mode, pData, dataLen, NULL, 0, pPub, &pubLen, pSig, &sigLen);

            /* WolfSSL Verify */
            retVal += wolfssl_verify(i, wolfMode, pData, dataLen, pPub, pubLen, pSig, sigLen);
            (void) DIGI_MEMSET(pSig, 0x00, sigLen);

            /* WolfSSL Sign */
            retVal += wolfssl_sign(i, wolfMode, pData, dataLen, pPub, &pubLen, pSig, &sigLen);

            /* Digicert Verify, no context */
            retVal += digicert_verify(i, mode, pData, dataLen, NULL, 0, pPub, pubLen, pSig, sigLen);
             (void) DIGI_MEMSET(pSig, 0x00, sigLen);
        }
    }

exit:

    (void) DIGICERT_freeDigicert();

    return retVal;
}
