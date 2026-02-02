/*
 * pqc_slhdsa_test.c
 *
 * Interopability test for SLH-DSA algorithms.
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
#include "../../crypto/pqc/slhdsa.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../../projects/crypto_interop_test/boringssl/include/openssl/slhdsa.h"

#ifndef PQC_SLHDSA_TEST_ITERATIONS
#define PQC_SLHDSA_TEST_ITERATIONS 50
#endif

/* ----------------------------------------------------------------------- */

static int bssl_sign(ubyte4 hint, ubyte *pData, ubyte4 dataLen, ubyte *pCtx, ubyte4 ctxLen,
                     ubyte *pPub, ubyte *pSig)
{
    int retVal = 0;
    int ret = 0;

    uint8_t priv[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES];

    /* generate a key first with basl */
    SLHDSA_SHA2_128S_generate_key(pPub, priv);

    /* sign with bssl */
    ret = SLHDSA_SHA2_128S_sign((uint8_t *) pSig, priv, (const uint8_t *) pData, dataLen,
                                (const uint8_t *) pCtx, ctxLen);
    if (1 != ret)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int bssl_verify(ubyte4 hint, ubyte *pData, ubyte4 dataLen, ubyte *pCtx, ubyte4 ctxLen,
                       ubyte *pPub, ubyte4 pubLen, ubyte *pSig, ubyte4 sigLen)
{
    int retVal = 0;
    int ret = 0;

    ret = SLHDSA_SHA2_128S_verify((const uint8_t *) pSig, sigLen, (const uint8_t *) pPub,
                                  (const uint8_t *) pData, dataLen, (const uint8_t *) pCtx, ctxLen);
    if (1 != ret)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int digicert_sign(ubyte4 hint, SLHDSAType mode, ubyte *pData, ubyte4 dataLen, ubyte *pCtx, ubyte4 ctxLen,
                         ubyte *pPub, ubyte4 *pPubLen, ubyte *pSig, ubyte4 *pSigLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;

    SLHDSACtx ctx = {0};
    size_t sigLen = 0;
    size_t pubLen = 0;

    /* Verify with us */
    status = SLHDSA_createCtx(mode, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_getSignatureLen(&ctx, &sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_getPublicKeyLen(&ctx, &pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_generateKeyPair(RANDOM_rngFun, g_pRandomContext, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_getPublicKey(&ctx, pPub, pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_signMessage(&ctx, pData, dataLen, RANDOM_rngFun, g_pRandomContext, pSig, sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    *pSigLen = sigLen;
    *pPubLen = pubLen;

exit:

    status = SLHDSA_destroyCtx(&ctx);
    retVal += UNITTEST_STATUS(hint, status);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int digicert_verify(ubyte4 hint, SLHDSAType mode, ubyte *pData, ubyte4 dataLen, ubyte *pCtx, ubyte4 ctxLen,
                           ubyte *pPub, ubyte4 pubLen, ubyte *pSig, ubyte4 sigLen)
{
    MSTATUS status = OK;
    int retVal = 0;

    SLHDSACtx ctx = {0};

    /* Verify with us */
    status = SLHDSA_createCtx(mode, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_setPublicKey(pPub, pubLen, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_verifyMessage(&ctx, pData, dataLen, pSig, sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

exit:

    status = SLHDSA_destroyCtx(&ctx);
    retVal += UNITTEST_STATUS(hint, status);

    return retVal;
}

/* ----------------------------------------------------------------------- */

int pqc_slhdsa_test_all()
{
    MSTATUS status = OK;
    int retVal = 0;
    int i = 0;
    SLHDSAType mode = SLHDSA_TYPE_SHA2_128S; /* only mode bssl has */

    ubyte pData[512]; /* space for a message and context */
    size_t dataLen = 0;
    ubyte *pCtx = NULL;
    size_t ctxLen = 0;

    ubyte pPub[32];   /* only for 128s or f */
    size_t pubLen = 0;

    ubyte pSig[7856]; /* only for 128s */
    size_t sigLen = 0;

    status = DIGICERT_initDigicert();
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    for (i = 0; i < PQC_SLHDSA_TEST_ITERATIONS; i++)
    {
        /* create a random msg and context, first just fill the buffer  */
        status = (MSTATUS) RANDOM_rngFun(g_pRandomContext, sizeof(pData), pData);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        /* use the last two bytes to pick random lengths from 0 to 255 */
        dataLen = (ubyte4) pData[511];

        /**** BSSL compatibility tests, for Sha2 128-s only ****/

        /* Digicert Sign with context */
        retVal += digicert_sign(i, mode, pData, dataLen, pCtx, ctxLen, pPub, &pubLen, pSig, &sigLen);

        /* bssl Verify with context */
        retVal += bssl_verify(i, pData, dataLen, pCtx, ctxLen, pPub, pubLen, pSig, sigLen);
        (void) DIGI_MEMSET(pSig, 0x00, sigLen);

        /* bssl Sign with context */
        retVal += bssl_sign(i, pData, dataLen, pCtx, ctxLen, pPub, pSig);
        pubLen = SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES; /* get lengths from bssl macros */
        sigLen = SLHDSA_SHA2_128S_SIGNATURE_BYTES;

        /* Digicert Verify with context */
        retVal += digicert_verify(i, mode, pData, dataLen, pCtx, ctxLen, pPub, pubLen, pSig, sigLen);
        (void) DIGI_MEMSET(pSig, 0x00, sigLen);
    }

exit:

    (void) DIGICERT_freeDigicert();

    return retVal;
}
