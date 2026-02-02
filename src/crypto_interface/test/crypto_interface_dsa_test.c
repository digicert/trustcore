/*
 * crypto_interface_dsa_test.c
 *
 * test cases for crypto interface API in dsa
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
#include "../../common/vlong.h"
#include "../../crypto/sha512.h"
#include "../../crypto/dsa.h"
#include "../../crypto/dsa2.h"
#include "../../crypto_interface/crypto_interface_dsa.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../common/random.h"
#include "../../crypto/nist_rng.h"
#endif

#if defined(__ENABLE_DIGICERT_DSA__) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static int testRoundTrip(randomContext *pRandomContext, ubyte4 keySize, ubyte4 qSize)
{
    int retVal = 0;
    MSTATUS status = OK;
    char pMsg[] = "Attack at dawn";
    ubyte4 msgLen = 14; /* we'll leave out the '\0' char */
    
    MDsaKeyTemplate template = {0};
    DSAKey *pPriv = NULL;
    DSAKey *pPub = NULL;
    
    ubyte *pR = NULL;
    ubyte4 rLen = 0;
    ubyte *pS = NULL;
    ubyte4 sLen = 0;
    ubyte4 sigLen = 0;
    
    intBoolean valid = FALSE;

    status = DSA_createKey(&pPriv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DSA_createKey(&pPub);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (224 == qSize)
    {
        status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pPriv, keySize, qSize, DSA_sha224, NULL);
    }
    else
    {
        status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pPriv, keySize, NULL);
    }
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pPriv, (ubyte *) pMsg, msgLen, NULL, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* quick check signature lengths agree */
    status = DSA_getSignatureLength(MOC_DSA(gpHwAccelCtx) pPriv, &sigLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, rLen, sigLen);
    retVal += UNITTEST_INT(__MOC_LINE__, sLen, sigLen);

    status = DSA_getKeyParametersAlloc(MOC_DSA(gpHwAccelCtx) pPriv, &template, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DSA_setKeyParametersAux(MOC_DSA(gpHwAccelCtx) pPub, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pPub, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }
    
    /* negative tests, invalid r */
    pR[rLen - 1]++;
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pPub, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (TRUE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }

    /* invalid s */
    pR[rLen - 1]--;
    pS[sLen - 1]++;
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pPub, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (TRUE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }

    /* different msg */
    pS[sLen - 1]--;
    *pMsg = 'a';
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pPub, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (TRUE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }
    
exit:

    status = DSA_freeKeyTemplate(pPriv, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    if (NULL != pPriv)
    {
        status = DSA_freeKey(&pPriv, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pPub)
    {
        status = DSA_freeKey(&pPub, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pR)
    {
        status = DIGI_FREE((void **) &pR);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pS)
    {
        status = DIGI_FREE((void **) &pS);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

static int testRoundTripDSA2(randomContext *pRandomContext, ubyte4 keySize, ubyte4 qSize)
{
    int retVal = 0;
    MSTATUS status = OK;
    char pMsg[] = "Attack at dawn";
    ubyte4 msgLen = 14; /* we'll leave out the '\0' char */
    
    ubyte pHash[512];
    ubyte4 hashLen = 512;
    
    MDsaKeyTemplate template = {0};
    DSAKey *pPriv = NULL;
    DSAKey *pPub = NULL;
    
    ubyte *pR = NULL;
    ubyte4 rLen = 0;
    ubyte *pS = NULL;
    ubyte4 sLen = 0;
    
    intBoolean valid = FALSE;
    
    status = SHA512_completeDigest(MOC_HASH(gpHwAccelCtx) pMsg, msgLen, pHash);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DSA_createKey(&pPriv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DSA_createKey(&pPub);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (224 == qSize)
    {
        status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pPriv, keySize, qSize, DSA_sha224, NULL);
    }
    else
    {
        status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pPriv, keySize, NULL);
    }
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) RANDOM_rngFun, pRandomContext, pPriv, pHash, hashLen, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DSA_getKeyParametersAlloc(MOC_DSA(gpHwAccelCtx) pPriv, &template, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DSA_setKeyParametersAux(MOC_DSA(gpHwAccelCtx) pPub, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pPub, pHash, hashLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }
    
    /* test the same hash but pre-truncated */
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pPub, pHash, qSize/8, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (FALSE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }
    
    /* negative tests, invalid r */
    pR[rLen - 1]++;
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pPub, pHash, hashLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (TRUE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }
    
    /* invalid s */
    pR[rLen - 1]--;
    pS[sLen - 1]++;
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pPub, pHash, hashLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (TRUE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }
    
    /* different hash */
    pHash[0]++;
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pPub, pHash, hashLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (TRUE == valid)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }
    
exit:
    
    status = DSA_freeKeyTemplate(pPriv, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    if (NULL != pPriv)
    {
        status = DSA_freeKey(&pPriv, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pPub)
    {
        status = DSA_freeKey(&pPub, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pR)
    {
        status = DIGI_FREE((void **) &pR);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pS)
    {
        status = DIGI_FREE((void **) &pS);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int testErrorCases(randomContext *pRandomContext)
{
    int retVal = 0;
    MSTATUS status = OK;
    char pMsg[] = "Attack at dawn";
    ubyte4 msgLen = 14; /* we'll leave out the '\0' char */
    
    MDsaKeyTemplate template = {0};
    DSAKey *pKey = NULL;
    
    ubyte *pR = NULL;
    ubyte4 rLen = 0;
    ubyte *pS = NULL;
    ubyte4 sLen = 0;

    intBoolean valid = FALSE;
    
    /******* DSA_createKey *******/

    status = DSA_createKey(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* properly create a key for further tests */
    status = DSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* DSA_generateKeyAux2 *******/

    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) NULL, pKey, 2048, 224, DSA_sha224, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, NULL, 2048, 224, DSA_sha224, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#ifdef __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 1024, 224, DSA_sha224, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
#else
    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 1024, 160, DSA_sha1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
#endif

    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 2047, 224, DSA_sha224, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 2049, 256, DSA_sha256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 3072, 224, DSA_sha224, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 2048, 256, DSA_sha224, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_HASH_TOO_SMALL);
    
    status = DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 3072, 256, DSA_sha224, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_HASH_TOO_SMALL);

    /******* DSA_generateKeyAux *******/
    
    status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) NULL, pKey, 2048, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, NULL, 2048, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 1023, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
   
#ifndef __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
    status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 1024, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
#endif
    
    status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 1566, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 3073, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    /* generate a key properly for further tests */
    status = DSA_generateKeyAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, 2048, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* DSA_computeSignatureAux *******/
    
    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) NULL, pKey, (ubyte *) pMsg, msgLen, NULL, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) pRandomContext, NULL, (ubyte *) pMsg, msgLen, NULL, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, NULL, msgLen, NULL, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, (ubyte *) pMsg, msgLen, NULL, NULL, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, (ubyte *) pMsg, msgLen, NULL, &pR, NULL, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, (ubyte *) pMsg, msgLen, NULL, &pR, &rLen, NULL, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignatureAux(MOC_DSA(gpHwAccelCtx) pRandomContext, pKey, (ubyte *) pMsg, msgLen, NULL, &pR, &rLen, &pS, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* DSA_computeSignature2Aux *******/
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) NULL, pRandomContext, pKey, (ubyte *) pMsg, msgLen, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) RANDOM_rngFun, pRandomContext, NULL, (ubyte *) pMsg, msgLen, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) RANDOM_rngFun, pRandomContext, pKey, NULL, msgLen, &pR, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) RANDOM_rngFun, pRandomContext, pKey, (ubyte *) pMsg, msgLen, NULL, &rLen, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) RANDOM_rngFun, pRandomContext, pKey, (ubyte *) pMsg, msgLen, &pR, NULL, &pS, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) RANDOM_rngFun, pRandomContext, pKey, (ubyte *) pMsg, msgLen, &pR, &rLen, NULL, &sLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_computeSignature2Aux(MOC_DSA(gpHwAccelCtx) RANDOM_rngFun, pRandomContext, pKey, (ubyte *) pMsg, msgLen, &pR, &rLen, &pS, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* DSA_getKeyParametersAlloc *******/

    status = DSA_getKeyParametersAlloc(MOC_DSA(gpHwAccelCtx) NULL, &template, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_getKeyParametersAlloc(MOC_DSA(gpHwAccelCtx) pKey, NULL, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* remove private key X for future test */
    status = VLONG_freeVlong(&DSA_X(pKey), NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DSA_getKeyParametersAlloc(MOC_DSA(gpHwAccelCtx) pKey, &template, MOC_GET_PRIVATE_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DSA_INVALID_PARAM);

    /******* DSA_setKeyParametersAux *******/

    status = DSA_setKeyParametersAux(MOC_DSA(gpHwAccelCtx) NULL, &template);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_setKeyParametersAux(MOC_DSA(gpHwAccelCtx) pKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* DSA_verifySignatureAux *******/
    
    /* set pR and pS to pMsg so they're non-null */
    pR = (ubyte *) pMsg;
    pS = (ubyte *) pMsg;
    
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) NULL, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pKey, NULL, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pKey, (ubyte *) pMsg, msgLen, NULL, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pKey, (ubyte *) pMsg, msgLen, pR, rLen, NULL, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignatureAux(MOC_DSA(gpHwAccelCtx) pKey, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* DSA_verifySignature2Aux *******/
    
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) NULL, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pKey, NULL, msgLen, pR, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pKey, (ubyte *) pMsg, msgLen, NULL, rLen, pS, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pKey, (ubyte *) pMsg, msgLen, pR, rLen, NULL, sLen, &valid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifySignature2Aux(MOC_DSA(gpHwAccelCtx) pKey, (ubyte *) pMsg, msgLen, pR, rLen, pS, sLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* DSA_freeKeyTemplate *******/

    /* no error cases */

    /******* DSA_freeKey ******/
    
    status = DSA_freeKey(NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
exit:
    
    (void) DSA_freeKey(&pKey, NULL);
    
    return retVal;
}
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static int testParamAndKeyGen(randomContext *pRand, ubyte4 pSize, ubyte4 qSize, DSAHashType hashType)
{
    int retVal = 0;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    MSTATUS status = OK;
    DSAKey *pCtx = NULL;
    intBoolean isValid = FALSE;

    status = CRYPTO_INTERFACE_DSA_createKey(&pCtx);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DSA_generateKeyAux2(MOC_DSA(gpHwAccelCtx) pRand, pCtx,
                                                  pSize, qSize, hashType, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DSA_verifyPrivateKey(MOC_DSA(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }
    isValid = FALSE;

    status = CRYPTO_INTERFACE_DSA_verifyPublicKey(MOC_DSA(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }
    isValid = FALSE;
    
    status = CRYPTO_INTERFACE_DSA_verifyKeyPair(MOC_DSA(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }
    
    /* simple neg test, further tests are more complex, maybe can be added later or covered by openssl */
    isValid = TRUE;

    status = VLONG_increment(DSA_X(pCtx), NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DSA_verifyKeyPair(MOC_DSA(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (TRUE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }
    
exit:

    status = CRYPTO_INTERFACE_DSA_freeKey(&pCtx, NULL);
    retVal += UNITTEST_STATUS(qSize, status);

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

    return retVal;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

int crypto_interface_dsa_test_init()
{
    int retVal = 0;
#if defined(__ENABLE_DIGICERT_DSA__) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    MSTATUS status = OK;
    int i = 0;
    randomContext *pRandomContext  = NULL;
  
    InitMocanaSetupInfo setupInfo = {0};
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    ubyte pGarbage[MOC_DEFAULT_NUM_ENTROPY_BYTES];
#endif
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif
    
    status = RANDOM_acquireContext(&pRandomContext);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    status = NIST_CTRDRBG_reseed(pRandomContext, pGarbage, MOC_DEFAULT_NUM_ENTROPY_BYTES, NULL, 0);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
#ifdef __ENABLE_DIGICERT_DSA_768__
    retVal += testRoundTrip(pRandomContext, 768, 128);
    retVal += testRoundTrip(pRandomContext, 768, 256);
#endif
    retVal += testRoundTrip(pRandomContext, 1024, 160);
#ifndef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    retVal += testRoundTripDSA2(pRandomContext, 1024, 160);
#endif
#endif

    retVal += testRoundTrip(pRandomContext, 2048, 224);

#ifndef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    retVal += testRoundTrip(pRandomContext, 2048, 256);
    retVal += testRoundTrip(pRandomContext, 3072, 256);
    
    retVal += testRoundTripDSA2(pRandomContext, 2048, 224);
    retVal += testRoundTripDSA2(pRandomContext, 2048, 256);
    retVal += testRoundTripDSA2(pRandomContext, 3072, 256);
#endif    

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    retVal += testParamAndKeyGen(pRandomContext, 1024, 160, DSA_sha1);
    retVal += testParamAndKeyGen(pRandomContext, 2048, 224, DSA_sha224);
    retVal += testParamAndKeyGen(pRandomContext, 2048, 256, DSA_sha256);
#endif

    retVal += testErrorCases(pRandomContext);

exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    RANDOM_releaseContext(&pRandomContext);

#endif
    return retVal;
}
