/*
 * mlkem_test.c
 *
 * test cases for ML-KEM
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
#include "../../crypto/pqc/mlkem.c"
#include "../../crypto/test/mlkem_data_inc.h"

/* ----------------------------------------------------------------------- */

/* for purposes of key validation tests a buffer of all 0xab is sufficient */
static sbyte4 keyValRngFun(void* rngFunArg, ubyte4 length, ubyte *buffer)
{
    return (sbyte4) DIGI_MEMSET(buffer, 0xab, length);
}

/* ----------------------------------------------------------------------- */

static MLKEMType algToMLKEMType(ubyte4 alg)
{
        if (alg == cid_PQC_MLKEM_512)
            return MLKEM_TYPE_512;
        else if (alg == cid_PQC_MLKEM_768)
            return MLKEM_TYPE_768;
        else if (alg == cid_PQC_MLKEM_1024)
            return MLKEM_TYPE_1024;

        return MLKEM_TYPE_ERR;
}

/* ----------------------------------------------------------------------- */

static int testMlkemKeyGen(MlkemGenVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    MlkemCtx *pCtx = NULL;
    MLKEMCtx outerCtx = {0};
    ubyte pDCopy[33];
 
    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;
    ubyte4 pubLen = 0;
    ubyte4 pubOffset = 0;

    /* vars for values from the vector */
    ubyte *pD = NULL;
    ubyte4 dLen = 0;
    ubyte *pZ = NULL;
    ubyte4 zLen = 0;
    ubyte *pExpPriv = NULL;
    ubyte4 expPrivLen = 0;
    ubyte *pExpPub = NULL;
    ubyte4 expPubLen = 0;

    if (cid_PQC_MLKEM_512 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem512;
    }
    else if (cid_PQC_MLKEM_768 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem768;
    }
    else if (cid_PQC_MLKEM_1024 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem1024;
    }

    /* We know the private key starts at the 12th bytes in the context, priv contains pub too */
    privLen = *(((ubyte4 *) pCtx) + 3);
    /* pubLen starts at the 8th bytes in the context */
    pubLen = *(((ubyte4 *) pCtx) + 2);
    /* its offset in the private key starts at the 4th byte */
    pubOffset = *(((ubyte4 *) pCtx) + 1);

    status = DIGI_MALLOC((void **)&pPriv, privLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pTestVector->pZ != NULL)
    {
        zLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pZ, &pZ);
    }
    if (pTestVector->pD != NULL)
    {
        dLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pD, &pD);
    }
    if (pTestVector->pDk != NULL)
    {
        expPrivLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pDk, &pExpPriv);
    }
    if (pTestVector->pEk != NULL)
    {
        expPubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pEk, &pExpPub);
    }

    /* MLKEM_keyGen_internal requires pD to have an extra byte of space, copy to pDCopy */
    (void) DIGI_MEMCPY(pDCopy, pD, 32);

    status = MLKEM_keyGen_internal(pCtx, pDCopy, pZ, pPriv);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* validate the private key */
    if (privLen != expPrivLen)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pPriv, pExpPriv, privLen, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* validate the public key */
    if (pubLen != expPubLen)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pPriv + pubOffset, pExpPub, pubLen, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* Test the validate method, put the key in the outer SLHDSACtx type for use in the API */
    status = MLKEM_createCtx(algToMLKEMType(pTestVector->mode), 0, &outerCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_setPrivateKey(pPriv, privLen, &outerCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = MLKEM_setPublicKey(pPriv + pubOffset, pubLen, &outerCtx);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;
    
    if (!MLKEM_verifyKeyPair(&outerCtx, keyValRngFun, NULL))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /***** Negative Tests *******/ 

    /* encKey = ek.Pke = (t, rho) */

    /* change t */
    outerCtx.encKey[0]++;
    if (MLKEM_verifyKeyPair(&outerCtx, keyValRngFun, NULL))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.encKey[0]--;

    /* change rho, last seed len, ie 32 byte */
    outerCtx.encKey[pCtx->ekPkeLen - 32]++;
    if (MLKEM_verifyKeyPair(&outerCtx, keyValRngFun, NULL))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.encKey[pCtx->ekPkeLen - 32]--;

    /* decKey = (dk.Pke, ek.Pke, h, z) */

    /* change dk */
    outerCtx.decKey[0]++;
    if (MLKEM_verifyKeyPair(&outerCtx, keyValRngFun, NULL))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.decKey[0]--;

    /* change ek */
    outerCtx.decKey[pCtx->dkPkeLen]++;
    if (MLKEM_verifyKeyPair(&outerCtx, keyValRngFun, NULL))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.decKey[pCtx->dkPkeLen]--;

    /* change h */
    outerCtx.decKey[pCtx->dkPkeLen + pCtx->ekPkeLen]++;
    if (MLKEM_verifyKeyPair(&outerCtx, keyValRngFun, NULL))
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }
    outerCtx.decKey[pCtx->dkPkeLen + pCtx->ekPkeLen]--;

    /* changing z won't matter, still a valid key */

exit:

    if (NULL != pPriv)
    {
        status = DIGI_FREE((void **)&pPriv);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pD)
    {
        status = DIGI_FREE((void **)&pD);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pZ)
    {
        status = DIGI_FREE((void **)&pZ);
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

    MLKEM_destroyCtx(&outerCtx);

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int testMlkemEncaps(MlkemEncapsVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    MlkemCtx *pCtx = NULL;
    ubyte pMCopy[64] = {0}; /* extra 32 bytes space required by encaps_internal */
    ubyte pSS[32] = {0}; /* 32 bytes for all modes */

    ubyte *pCipher = NULL;
    ubyte4 cipherLen = 0;
 
    /* vars for values from the vector */
    ubyte *pEk = NULL;
    ubyte4 ekLen = 0;
    ubyte *pC = NULL;
    ubyte4 cLen = 0;
    ubyte *pK = NULL;
    ubyte4 kLen = 0;
    ubyte *pM = NULL;
    ubyte4 mLen = 0;

    if (cid_PQC_MLKEM_512 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem512;
    }
    else if (cid_PQC_MLKEM_768 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem768;
    }
    else if (cid_PQC_MLKEM_1024 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem1024;
    }

    /* We know the cipher length starts at the 16th bytes in the context */
    cipherLen = *(((ubyte4 *) pCtx) + 4);

    status = DIGI_MALLOC((void **)&pCipher, cipherLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (pTestVector->pEk != NULL)
    {
        ekLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pEk, &pEk);
    }
    if (pTestVector->pC != NULL)
    {
        cLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pC, &pC);
    }
    if (pTestVector->pK != NULL)
    {
        kLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pK, &pK);
    }
    if (pTestVector->pM != NULL)
    {
        mLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pM, &pM);
    }

    /* copy m over to a buffer with the extra space */
    (void) DIGI_MEMCPY(pMCopy, pM, mLen);
    status = MLKEM_encaps_internal(pCtx, pEk, pMCopy, pCipher, pSS);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* compare ciphertext */
    if (cipherLen != cLen)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit; 
    }

    status = DIGI_MEMCMP(pCipher, pC, cipherLen, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* compare shared secret */
    status = DIGI_MEMCMP(pSS, pK, 32, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:

    if (NULL != pCipher)
    {
        status = DIGI_FREE((void **)&pCipher);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pEk)
    {
        status = DIGI_FREE((void **)&pEk);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pC)
    {
        status = DIGI_FREE((void **)&pC);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pK)
    {
        status = DIGI_FREE((void **)&pK);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pM)
    {
        status = DIGI_FREE((void **)&pM);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}

/* ----------------------------------------------------------------------- */

static int testMlkemDecaps(MlkemDecapsVector *pTestVector, ubyte4 hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    MlkemCtx *pCtx = NULL;
    char *pPriv = NULL;
    ubyte *pDk = NULL;
    ubyte4 dkLen = 0;
    ubyte pSS[32] = {0}; /* 32 bytes for all modes */
 
    /* vars for values from the vector */
    ubyte *pC = NULL;
    ubyte4 cLen = 0;
    ubyte *pK = NULL;
    ubyte4 kLen = 0;

    if (cid_PQC_MLKEM_512 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem512;
        pPriv = gMlkemDk512;
    }
    else if (cid_PQC_MLKEM_768 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem768;
        pPriv = gMlkemDk768;
    }
    else if (cid_PQC_MLKEM_1024 == pTestVector->mode)
    {
        pCtx = (MlkemCtx *) &gMlkem1024;
        pPriv = gMlkemDk1024;
    }

    dkLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pPriv, &pDk);

    if (pTestVector->pC != NULL)
    {
        cLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pC, &pC);
    }
    if (pTestVector->pK != NULL)
    {
        kLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pK, &pK);
    }
    
    status = MLKEM_decaps_internal(pCtx, pDk, pC, pSS);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* compare shared secret, test vectors that use the fixed fallback secret
       still return OK in the above call but can still be validated via gdb etc */
    status = DIGI_MEMCMP(pSS, pK, 32, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:

    if (NULL != pDk)
    {
        status = DIGI_FREE((void **)&pDk);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pC)
    {
        status = DIGI_FREE((void **)&pC);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pK)
    {
        status = DIGI_FREE((void **)&pK);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}
#endif

/* ----------------------------------------------------------------------- */

int mlkem_test_init()
{
    int retVal = 0;

    /* no initMocana needed, no rng used */
#ifdef __ENABLE_DIGICERT_PQC_CAVP_TEST__
    
    int i;

    for (i = 0; i < COUNTOF(gMlkemGenTest); i++)
    {
        retVal += testMlkemKeyGen(&gMlkemGenTest[i], i);
    }

    for (i = 0; i < COUNTOF(gMlkemEncapsTest); i++)
    {
        retVal += testMlkemEncaps(&gMlkemEncapsTest[i], i);
    }

    for (i = 0; i < COUNTOF(gMlkemDecapsTest); i++)
    {
        retVal += testMlkemDecaps(&gMlkemDecapsTest[i], i);
    }
#endif

    return retVal;
}
