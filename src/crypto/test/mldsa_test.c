/*
 * mldsa_test.c
 *
 * test cases for ML-DSA
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_DIGICERT_PQC_CAVP_TEST__

/* include the .c file since we test the internal static methods */
#include "../../crypto/pqc/mldsa.c"
#include "../../crypto/test/mldsa_data_inc.h"

/* ----------------------------------------------------------------------- */

static int testMldsaKeyGen(MldsaGenVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    MLDSACtx ctx = {0};
    MLDSAType type = 0;
    size_t s1_len; /* for MLDSA_verifyKeyPair negative tests */
    size_t s2_len;

    ubyte *pSk = NULL;
    size_t skLen = 0;
    ubyte *pPk = NULL;
    size_t pkLen = 0;

    /* vars for values from the vector */
    ubyte *pRng = NULL;
    ubyte4 rngLen;
    ubyte *pExpPriv = NULL;
    ubyte4 expPrivLen;
    ubyte *pExpPub = NULL;
    ubyte4 expPubLen;

    if (cid_PQC_MLDSA_44 == pTestVector->mode)
    {
        type = MLDSA_TYPE_44;
        s1_len = 32 * 3 * 4; /* 32 * bitlen(2 eta) * l */
        s2_len = 32 * 3 * 4; /* 32 * bitlen(2 eta) * k */
        skLen = 2560;
    }
    else if (cid_PQC_MLDSA_65 == pTestVector->mode)
    {
        type = MLDSA_TYPE_65;
        s1_len = 32 * 4 * 5;
        s2_len = 32 * 4 * 6;
        skLen = 4032;
    }
    else if (cid_PQC_MLDSA_87 == pTestVector->mode)
    {
        type = MLDSA_TYPE_87;
        s1_len = 32 * 3 * 7;
        s2_len = 32 * 3 * 8;
        skLen = 4896;
    }

    status = MLDSA_createCtx(type, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* We know the public key and private key lengths are the 12th and 16th bytes in the context */
    status = MLDSA_getPublicKeyLen(&ctx, &pkLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pSk, skLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pPk, pkLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pTestVector->pRng != NULL)
    {
        rngLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pRng, &pRng);
    }
    if (pTestVector->pPriv != NULL)
    {
        expPrivLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPriv, &pExpPriv);
    }
    if (pTestVector->pPub != NULL)
    {
        expPubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPub, &pExpPub);
    }

    status = MLDSA_keyGen_internal(&ctx, pRng, pSk, pPk);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* validate the private key */
    if (skLen != expPrivLen)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pSk, pExpPriv, skLen, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* validate the public key */
    if (pkLen != expPubLen)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pPk, pExpPub, pkLen, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* Test the validate method, put the key in the context for use in the API */
    status = MLDSA_setPrivateKey(pRng, rngLen, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (!MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /***** Negative Tests *******/ 

    /* sk = (rho, K, tr, s1, s2, t0) */

    /* change rho */
    ctx.privKey[0]++;
    if (MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    ctx.privKey[0]--;

    /* changing K doesn't change the rest of the keys, so nothing to validate */

    /* Change tr */
    ctx.privKey[64]++;
    if (MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    ctx.privKey[64]--;

    /* change s1 */
    ctx.privKey[128]++;
    if (MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    ctx.privKey[128]--;

    /* change s2 */
    ctx.privKey[128 + s1_len]++;
    if (MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    ctx.privKey[128 + s1_len]--;

    /* change t0 */
    ctx.privKey[128 + s1_len + s2_len]++;
    if (MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    ctx.privKey[128 + s1_len + s2_len]--;

    /* pk = (rho, t1) */

    /* change rho */
    ctx.pubKey[0]++;
    if (MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    ctx.pubKey[0]--;

    /* change t1 */
    ctx.pubKey[32]++;
    if (MLDSA_verifyKeyPair(&ctx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:

    if (NULL != pSk)
    {
        status = DIGI_FREE((void **)&pSk);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pPk)
    {
        status = DIGI_FREE((void **)&pPk);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pRng)
    {
        status = DIGI_FREE((void **)&pRng);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pExpPriv)
    {
        status = DIGI_FREE((void **)&pExpPriv);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pExpPub)
    {
        status = DIGI_FREE((void **)&pExpPub);
        retVal += UNITTEST_STATUS(hint, status);
    }

    MLDSA_destroyCtx(&ctx);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int testMldsaSig(MldsaSignVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    ubyte pRnd[32] = {0};       /* deterministic mode rnd is all zeros */
    MLDSACtx ctx = {0};
    MLDSAType type = 0;

    ubyte *pSig = NULL;
    size_t sigLen = 0;

    /* vars for values from the vector */
    ubyte *pRng = NULL;
    ubyte4 rngLen = 0;
    ubyte *pPriv = NULL;
    ubyte4 privLen;
    ubyte *pMsg = NULL;
    ubyte4 msgLen;
    ubyte *pExpSig = NULL;
    ubyte4 expSigLen;

    if (cid_PQC_MLDSA_44 == pTestVector->mode)
    {
        type = MLDSA_TYPE_44;
    }
    else if (cid_PQC_MLDSA_65 == pTestVector->mode)
    {
        type = MLDSA_TYPE_65;
    }
    else if (cid_PQC_MLDSA_87 == pTestVector->mode)
    {
        type = MLDSA_TYPE_87;
    }

    status = MLDSA_createCtx(type, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* We know the signature length starts at the 20th bytes in the context */
    status = MLDSA_getSignatureLen(&ctx, &sigLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pSig, sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pTestVector->pRng != NULL)
    {
        rngLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pRng, &pRng);
        if (rngLen != 32) /* sanity check */
        {
            retVal += UNITTEST_STATUS(hint, -1); /* force error */
            goto exit;
        }

        (void) DIGI_MEMCPY(pRnd, pRng, 32);
    }

    if (pTestVector->pPriv != NULL)
    {
        privLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPriv, &pPriv);
    }
    if (pTestVector->pMsg != NULL)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pMsg, &pMsg);
    }
    if (pTestVector->pSig != NULL)
    {
        expSigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSig, &pExpSig);
    }

    status = DIGI_MALLOC_MEMCPY((void **) &ctx.privKey, privLen, (void *) pPriv, privLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    ctx.privKeyLen = privLen;
    status = MLDSA_sign_internal(&ctx, NULL, pMsg, msgLen, pRnd, pSig);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (sigLen != expSigLen)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pSig, pExpSig, sigLen, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:

    if (NULL != pSig)
    {
        status = DIGI_FREE((void **)&pSig);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pRng)
    {
        status = DIGI_FREE((void **)&pRng);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pPriv)
    {
        status = DIGI_FREE((void **)&pPriv);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pMsg)
    {
        status = DIGI_FREE((void **)&pMsg);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pExpSig)
    {
        status = DIGI_FREE((void **)&pExpSig);
        retVal += UNITTEST_STATUS(hint, status);
    }

    MLDSA_destroyCtx(&ctx);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int testMldsaVerify(MldsaVerifyVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    char *pPk = NULL;
    ubyte4 vStatus = 1;
    MLDSACtx ctx = {0};
    MLDSAType type = 0;

    /* vars for values from the vector */
    ubyte *pPub = NULL;
    size_t pubLen;
    ubyte *pMsg = NULL;
    size_t msgLen;
    ubyte *pSig = NULL;
    size_t sigLen = 0;

    if (cid_PQC_MLDSA_44 == pTestVector->mode)
    {
        pPk = gMldsaPk44;
        type = MLDSA_TYPE_44;
    }
    else if (cid_PQC_MLDSA_65 == pTestVector->mode)
    {
        pPk = gMldsaPk65;
        type = MLDSA_TYPE_65;
    }
    else if (cid_PQC_MLDSA_87 == pTestVector->mode)
    {
        pPk = gMldsaPk87;
        type = MLDSA_TYPE_87;
    }

    pubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pPk, &pPub);

    if (pTestVector->pMsg != NULL)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pMsg, &pMsg);
    }
    if (pTestVector->pSig != NULL)
    {
        sigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSig, &pSig);
    }

    status = MLDSA_createCtx(type, 0, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_setPublicKey(pPub, pubLen, &ctx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLDSA_verify_internal(&ctx, NULL, pMsg, msgLen, pSig, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pTestVector->pass)
    {
        retVal += UNITTEST_INT(hint, vStatus, 0);
    }
    else
    {
        if (0 == vStatus)
        {
            retVal += UNITTEST_STATUS(hint, -1); /* force error */
        }
    }

exit:

    if (NULL != pPub)
    {
        status = DIGI_FREE((void **)&pPub);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pMsg)
    {
        status = DIGI_FREE((void **)&pMsg);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pSig)
    {
        status = DIGI_FREE((void **)&pSig);
        retVal += UNITTEST_STATUS(hint, status);
    }

    MLDSA_destroyCtx(&ctx);

    return retVal;
}
#endif

/* ----------------------------------------------------------------------- */

int mldsa_test_init()
{
    int retVal = 0;

    /* no initMocana needed, no rng used */
#ifdef __ENABLE_DIGICERT_PQC_CAVP_TEST__

    int i;

    for (i = 0; i < COUNTOF(gMldsaGenTest); i++)
    {
        retVal += testMldsaKeyGen(&gMldsaGenTest[i], i);
    }

    for (i = 0; i < COUNTOF(gMldsaSigTest); i++)
    {
        retVal += testMldsaSig(&gMldsaSigTest[i], i);
    }

    for (i = 0; i < COUNTOF(gMldsaVerifyTest); i++)
    {
        retVal += testMldsaVerify(&gMldsaVerifyTest[i], i);
    }

#endif

    return retVal;
}
