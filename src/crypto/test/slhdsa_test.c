/*
 * slhdsa_test.c
 *
 * test cases for SLH-DSA
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
#include "../../crypto/pqc/slhdsa.c"
#include "../../crypto/test/slhdsa_data_inc.h"

/* ----------------------------------------------------------------------- */

static SLHDSAType algToSLHDSAType(ubyte4 alg)
{
    switch (alg) {
        case cid_PQC_SLHDSA_SHA2_128S:
            return SLHDSA_TYPE_SHA2_128S;
        case cid_PQC_SLHDSA_SHA2_128F:
            return SLHDSA_TYPE_SHA2_128F;
        case cid_PQC_SLHDSA_SHAKE_128S:
            return SLHDSA_TYPE_SHAKE_128S;
        case cid_PQC_SLHDSA_SHAKE_128F:
            return SLHDSA_TYPE_SHAKE_128F;
        case cid_PQC_SLHDSA_SHA2_192S:
            return SLHDSA_TYPE_SHA2_192S;
        case cid_PQC_SLHDSA_SHA2_192F:
            return SLHDSA_TYPE_SHA2_192F;
        case cid_PQC_SLHDSA_SHAKE_192S:
            return SLHDSA_TYPE_SHAKE_192S;
        case cid_PQC_SLHDSA_SHAKE_192F:
            return SLHDSA_TYPE_SHAKE_192F;
        case cid_PQC_SLHDSA_SHA2_256S:
            return SLHDSA_TYPE_SHA2_256S;
        case cid_PQC_SLHDSA_SHA2_256F:
            return SLHDSA_TYPE_SHA2_256F;
        case cid_PQC_SLHDSA_SHAKE_256S:
            return SLHDSA_TYPE_SHAKE_256S;
        case cid_PQC_SLHDSA_SHAKE_256F:
            return SLHDSA_TYPE_SHAKE_256F;
        default:
            return SLHDSA_TYPE_ERR;
    }
}

static MSTATUS getCtx(ubyte mode, SlhdsaCtx **ppCtx)
{
    if (cid_PQC_SLHDSA_SHA2_128S == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaSha128s;
    }
    else if (cid_PQC_SLHDSA_SHA2_128F == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaSha128f;
    }    
    else if (cid_PQC_SLHDSA_SHA2_192S == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaSha192s;
    }
    else if (cid_PQC_SLHDSA_SHA2_192F == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaSha192f;
    }
    else if (cid_PQC_SLHDSA_SHA2_256S == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaSha256s;
    }
    else if (cid_PQC_SLHDSA_SHA2_256F == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaSha256f;
    }
    else if (cid_PQC_SLHDSA_SHAKE_128S == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaShake128s;
    }
    else if (cid_PQC_SLHDSA_SHAKE_128F == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaShake128f;
    }    
    else if (cid_PQC_SLHDSA_SHAKE_192S == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaShake192s;
    }
    else if (cid_PQC_SLHDSA_SHAKE_192F == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaShake192f;
    }
    else if (cid_PQC_SLHDSA_SHAKE_256S == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaShake256s;
    }
    else if (cid_PQC_SLHDSA_SHAKE_256F == mode)
    {
        *ppCtx = (SlhdsaCtx *) &gSlhdsaShake256f;
    }
    else
    {
        return ERR_INVALID_INPUT;
    }

    return OK;
}

/* ----------------------------------------------------------------------- */

static int testSlhdsaKeyGen(SlhdsaGenVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    SlhdsaCtx *pCtx = NULL;
    SLHDSACtx outerCtx = {0};

    ubyte pSk[128]; /* big enough for any mode */
 
    /* vars for values from the vector */
    ubyte *pSkSeed = NULL;
    ubyte4 skSeedLen;
    ubyte *pSkPrf = NULL;
    ubyte4 skPrfLen;
    ubyte *pPkSeed = NULL;
    ubyte4 pkSeedLen;
    ubyte *pExpPriv = NULL;
    ubyte4 expPrivLen;
    ubyte *pExpPub = NULL;
    ubyte4 expPubLen;

    status = getCtx(pTestVector->mode, &pCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;
    
    if (pTestVector->pSkSeed != NULL)
    {
        skSeedLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSkSeed, &pSkSeed);
    }
    if (pTestVector->pSkPrf != NULL)
    {
        skPrfLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSkPrf, &pSkPrf);
    }
    if (pTestVector->pPkSeed != NULL)
    {
        pkSeedLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPkSeed, &pPkSeed);
    }
    if (pTestVector->pSk != NULL)
    {
        expPrivLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSk, &pExpPriv);
    }
    if (pTestVector->pPk != NULL)
    {
        expPubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPk, &pExpPub);
    }

    /* keygen internal requires the seeds to be in a single buffer */
    (void) DIGI_MEMCPY(pSk, pSkSeed, pCtx->n);
    (void) DIGI_MEMCPY(pSk + pCtx->n, pSkPrf, pCtx->n);
    (void) DIGI_MEMCPY(pSk + 2 * pCtx->n, pPkSeed, pCtx->n); 

    status = SLHDSA_keygen_internal(pCtx, pSk);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* pSk now contains the full private key, the second half of which is the public key */

    /* validate the private key, we know it's length is 4n */
    status = DIGI_MEMCMP(pSk, pExpPriv, 4 * pCtx->n, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* validate the public key, we know its length is 2n */
    status = DIGI_MEMCMP(pSk + 2 * pCtx->n, pExpPub, 2 * pCtx->n, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* Test the validate method, put the key in the outer SLHDSACtx type for use in the API */
    status = SLHDSA_createCtx(algToSLHDSAType(pTestVector->mode), 0, &outerCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_setPrivateKey(pSk, 4 * pCtx->n, &outerCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = SLHDSA_setPublicKey(pSk + 2 * pCtx->n, 2 * pCtx->n, &outerCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;
    
    if (!SLHDSA_verifyKeyPair(&outerCtx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /***** Negative Tests *******/ 

    /* sk = (sk.seed, sk.prf, pk.seed, pk.root), each has length n */

    /* change sk.seed */
    outerCtx.privKey[0]++;
    if (SLHDSA_verifyKeyPair(&outerCtx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.privKey[0]--;

    /* pk.root does not depend on sk.prf, nothing to validate */

    /* change pk.seed */
    outerCtx.privKey[2 * pCtx->n]++;
    if (SLHDSA_verifyKeyPair(&outerCtx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.privKey[2 * pCtx->n]--;

    /* change pk.root */
    outerCtx.privKey[3 * pCtx->n]++;
    if (SLHDSA_verifyKeyPair(&outerCtx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.privKey[3 * pCtx->n]--;

    /* change pk.seed in the public key */
    outerCtx.pubKey[0]++;    
    if (SLHDSA_verifyKeyPair(&outerCtx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.pubKey[0]--;

    /* change pk.root in the public key */
    outerCtx.pubKey[pCtx->n]++;    
    if (SLHDSA_verifyKeyPair(&outerCtx))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:

    if (NULL != pSkSeed)
    {
        status = DIGI_FREE((void **)&pSkSeed);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pSkPrf)
    {
        status = DIGI_FREE((void **)&pSkPrf);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pPkSeed)
    {
        status = DIGI_FREE((void **)&pPkSeed);
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

    SLHDSA_destroyCtx(&outerCtx);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int testSlhdsaSig(SlhdsaSignVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    SlhdsaCtx *pCtx = NULL;
    ubyte pMsgPrefix[96] = {0}; /* space for 3 seeds to be prepended */
    ubyte4 n = 0;

    ubyte *pSig = NULL;

    /* vars for values from the vector */
    ubyte *pSk = NULL;
    ubyte4 skLen = 0;
    ubyte *pRng = NULL;
    ubyte4 rngLen = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte *pExpSig = NULL;
    ubyte4 expSigLen = 0;

    status = getCtx(pTestVector->mode, &pCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pSig, pCtx->sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pTestVector->pSk != NULL)
    {
        skLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSk, &pSk);
    }
    if (pTestVector->pRng != NULL)
    {
        rngLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pRng, &pRng);
    }
    if (pTestVector->pMsg != NULL)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pMsg, &pMsg);
    }
    if (pTestVector->pSig != NULL)
    {
        expSigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSig, &pExpSig);
    }

    /* we can get block length from the key length */
    n = skLen/4;

    if (rngLen)
    {
        /* non-deterministic, prepend the rng data */
        (void) DIGI_MEMCPY(pMsgPrefix + 2*n, pRng, n);
    }
    else
    {
        /* deterministic version, use PK.seed, ie 3rd block in SK */
        (void) DIGI_MEMCPY(pMsgPrefix + 2*n, pSk + 2*n, n);
    }
    status = SLHDSA_sign_internal(pCtx, pSk, pMsgPrefix, 3*n, pMsg, msgLen, pSig);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pCtx->sigLen != expSigLen)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit; 
    }

    status = DIGI_MEMCMP(pSig, pExpSig, expSigLen, &compare);
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

    if (NULL != pSk)
    {
        status = DIGI_FREE((void **)&pSk);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pRng)
    {
        status = DIGI_FREE((void **)&pRng);
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

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int testSlhdsaVerify(SlhdsaVerifyVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    SlhdsaCtx *pCtx = NULL;
    ubyte4 vStatus = 1;
    ubyte pMsgPrefix[96] = {0}; /* space for 3 seeds to be prepended */
    ubyte4 n = 0;

    /* vars for values from the vector */
    ubyte *pPk = NULL;
    ubyte4 pkLen;
    ubyte *pMsg = NULL;
    ubyte4 msgLen;
    ubyte *pSig = NULL;
    ubyte4 sigLen;

    status = getCtx(pTestVector->mode, &pCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pTestVector->pPk != NULL)
    {
        pkLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPk, &pPk);
    }
    if (pTestVector->pMsg != NULL)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pMsg, &pMsg);
    }
    if (pTestVector->pSig != NULL)
    {
        sigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSig, &pSig);
    }

    /* we can get block length from the key length */
    n = pkLen/2;
    status = SLHDSA_verify_internal(pCtx, pPk, pMsgPrefix, 3*n, pMsg, msgLen, pSig, -1, &vStatus);
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

    if (NULL != pPk)
    {
        status = DIGI_FREE((void **)&pPk);
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

    return retVal;
}
#endif

/* ----------------------------------------------------------------------- */

int slhdsa_test_init()
{
    int retVal = 0;

    /* no initMocana needed, no rng used */
#ifdef __ENABLE_DIGICERT_PQC_CAVP_TEST__
    
    int i;

    for (i = 0; i < COUNTOF(gSlhdsaGenTest); i++)
    {
        retVal += testSlhdsaKeyGen(&gSlhdsaGenTest[i], i);
    }

    for (i = 0; i < COUNTOF(gSlhdsaSigTest); i++)
    {
        retVal += testSlhdsaSig(&gSlhdsaSigTest[i], i);
    }

    for (i = 0; i < COUNTOF(gSlhdsaVerifyTest); i++)
    {
        retVal += testSlhdsaVerify(&gSlhdsaVerifyTest[i], i);
    }

#endif

    return retVal;
}
