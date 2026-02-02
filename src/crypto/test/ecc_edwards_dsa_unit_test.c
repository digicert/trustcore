/*
 * ecc_edwards_dsa_unit_test.c
 *
 *   unit test for ecc_edwards_dsa.c
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
#include "../../crypto/sha3.h"
#include "../../crypto/sha512.h"
#include "../../crypto/ecc_edwards_dsa.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;
static int gTestCurve = 0;
static int gShaSuite = 0;   /* 0 for digest only, 1 for evp */

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector_p%d and sha suite %d\n", gCurrentVector, gTestCurve, gShaSuite); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector_p%d and sha suite %d\n", gCurrentVector, gTestCurve, gShaSuite); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef struct TestVector
{
    char *pPrivKey;
    char *pPubKey;
    char *pMsgDigest;
    char *pSignature;
    char *pCtx;
    byteBoolean preHash;
    ubyte4 verifyStatus;
    
} TestVector;

#ifdef __ENABLE_DIGICERT_SHA3__

/* shake256 wrappers of sha3 in the BulkHashAlgo form */
static MSTATUS shake256_init(void *pCtx)
{
    return SHA3_initDigest((SHA3_CTX *) pCtx, MOCANA_SHA3_MODE_SHAKE256);
}

static MSTATUS shake256_digest(ubyte *pMessage, ubyte4 messageLen, ubyte *pResult, ubyte4 desiredResultLen)
{
    return SHA3_completeDigest(MOCANA_SHA3_MODE_SHAKE256, pMessage, messageLen, pResult, desiredResultLen);
}

#endif /* __ENABLE_DIGICERT_SHA3__ */


#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
#include "ecc_edwards_dsa_data_25519_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
#include "ecc_edwards_dsa_data_448_inc.h"
#endif


static int testSign(edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pExpectedSig, ubyte4 expectedSigLen, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    ubyte pSignature[57*2] = {0}; /* big enough for either curve */
    ubyte4 signatureLen;
    
    /* Call with NULL pSignature to get the singatureLen */
    status = edDSA_Sign(pKey, pMessage, messageLen, NULL, 0, &signatureLen, pShaSuite, preHash, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
    
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, preHash, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
    
    status = DIGI_MEMCMP(pSignature, pExpectedSig, signatureLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:

    return retVal;
}


static int testSignEVP(edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pExpectedSig, ubyte4 expectedSigLen, BulkHashAlgo *pShaSuite, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    edDSA_CTX signCtx = {0};
    
    ubyte pSignature[57*2] = {0}; /* big enough for either curve */
    ubyte4 signatureLen;
    
    /* Call with NULL pSignature to get the singatureLen */
    status = edDSA_initSignPreHash(&signCtx, pKey, pShaSuite, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edDSA_update(&signCtx, pMessage, messageLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edDSA_finalSign(&signCtx, NULL, 0, &signatureLen, NULL);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);

    status = edDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), &signatureLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
    
    status = DIGI_MEMCMP(pSignature, pExpectedSig, signatureLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:

    return retVal;
}

static int testVerifyEVP(edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature, ubyte4 signatureLen, ubyte4 expectedVerifyStatus, BulkHashAlgo *pShaSuite, 
                         byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 verifyStatus;
    
    edDSA_CTX verifyCtx = {0};
    
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, pShaSuite, preHash, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /*
     edDSA_update's message buffering is clearly relegated to the hash method used.
     The unit test for the hash method therefore has the responsibility for testing
     the buffering of pMessage into various size chunks. We will just make one straight call
     to edDSA_update.
     */
    status = edDSA_update(&verifyCtx, pMessage, messageLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edDSA_finalVerify(&verifyCtx, &verifyStatus, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, verifyStatus, expectedVerifyStatus);
    
exit:
    
    return retVal;
}

static int testVerifyOneShot(edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature, ubyte4 signatureLen, ubyte4 expectedVerifyStatus, 
                             BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 verifyStatus;
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, preHash, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, verifyStatus, expectedVerifyStatus);
    
exit:
    
    return retVal;
}

static int knownAnswerTest(TestVector *pTestVector, edECCCurve curve, BulkHashAlgo *pShaSuite)
{
    MSTATUS status = OK;
    int retVal = 0;
    
    edECCKey *pPrivKey = NULL;
    edECCKey *pPubKey = NULL;
    
    ubyte *pPrivBytes = NULL;
    ubyte4 privLen = 0;
    
    ubyte *pPubBytes = NULL;
    ubyte4 pubLen = 0;
    
    ubyte *pMsgDigestBytes = NULL;
    ubyte4 msgDigestLen = 0;
    
    ubyte *pSignatureBytes = NULL;
    ubyte4 sigLen = 0;

    ubyte *pCtx = NULL;
    ubyte4 ctxLen = 0;
    
    ubyte4 expectedVerifyStatus = pTestVector->verifyStatus;
    
    if (NULL != pTestVector->pPrivKey)
        privLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivKey, &pPrivBytes);
    if (NULL != pTestVector->pPubKey)
        pubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPubKey, &pPubBytes);
    if (NULL != pTestVector->pMsgDigest)
        msgDigestLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pMsgDigest, &pMsgDigestBytes);
    if (NULL != pTestVector->pSignature)
        sigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSignature, &pSignatureBytes);
    if (NULL != pTestVector->pCtx)
        ctxLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pCtx, &pCtx);

    if (NULL != pPrivBytes && NULL != pPubBytes)
    {
        status = edECC_newKey(&pPrivKey, curve, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = edECC_setKeyParameters(pPrivKey, pPubBytes, pubLen, pPrivBytes, privLen, NULL, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != pPubBytes)
    {
        status = edECC_newKey(&pPubKey, curve, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = edECC_setKeyParameters(pPubKey, pPubBytes, pubLen, NULL, 0, NULL, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* If there is a private key we test both sign and verify. Otherwise we test just verify */
    
    if (NULL != pPrivKey)
    {
        retVal += testSign(pPrivKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, pShaSuite, pTestVector->preHash, pCtx, ctxLen);

        if (NULL != pShaSuite->initFunc && pTestVector->preHash)
        {
            retVal += testSignEVP(pPrivKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, pShaSuite, pCtx, ctxLen);
        }
    }
    
    retVal += testVerifyOneShot(pPubKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, expectedVerifyStatus, pShaSuite, pTestVector->preHash, pCtx, ctxLen);
            
    if (NULL != pShaSuite->initFunc)  /* testVerifyEVP only if evp methods are available */
    {
        retVal += testVerifyEVP(pPubKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, expectedVerifyStatus, pShaSuite, pTestVector->preHash, pCtx, ctxLen);
    }
    
exit:
    
    if (NULL != pPrivKey)
    {
        status = edECC_deleteKey(&pPrivKey, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubKey)
    {
        status = edECC_deleteKey(&pPubKey, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPrivBytes)
    {
        status = DIGI_FREE((void **) &pPrivBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubBytes)
    {
        status = DIGI_FREE((void **) &pPubBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pMsgDigestBytes)
    {
        status = DIGI_FREE((void **) &pMsgDigestBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pSignatureBytes)
    {
        status = DIGI_FREE((void **) &pSignatureBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pCtx)
    {
        status = DIGI_FREE((void **) &pCtx);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


static int testErrorCases(edECCCurve curve, BulkHashAlgo *pShaSuite)
{
    MSTATUS status;
    int retVal = 0;
    
    edECCKey keyUnalloc = {0};
    edECCKey *pKey = NULL;
    
    ubyte pKeyBuffer[57] = {0};    /* big enough for either curve */
    
    ubyte pMessage[1] = {0};
    ubyte4 messageLen = 1;
    
    ubyte4 signatureLen = 0;
    
    ubyte pSignature[114] = {0};  /* big enough for either curve */
    ubyte pCtx[1] = {0}; 

    ubyte4 verifyStatus = 0;
    
    edDSA_CTX verifyCtx = {0};
    edDSA_CTX signCtx = {0};
    
    keyUnalloc.curve = curve;
    
    /* create a valid key for testing */
    
    status = edECC_newKey(&pKey, curve, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    pKey->isPrivate = TRUE;
    
    /******* edDSA_Sign *******/
    
    /* null params */
    status = edDSA_Sign(NULL, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_Sign(pKey, NULL, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_Sign(pKey, pMessage, messageLen, NULL, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), NULL, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, NULL, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* wrong curve alg id */
    pKey->curve = curveX25519;
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_CURVE_ID_FOR_ALG);
    pKey->curve = curve;
    
    /* invalid sha suite */
    pShaSuite->digestXOFFunc = NULL;
    pShaSuite->freeFunc = NULL;
    
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);
    
    /* complete the shaSuite for future tests */
    if (curveEd25519 == curve)
    {
#ifndef __DISABLE_DIGICERT_SHA512__
        pShaSuite->freeFunc = &SHA512_freeDigest;
#else
        (void) curve;
#endif
    }
#ifdef __ENABLE_DIGICERT_SHA3__
    else  /* curveEd448 == curve */
    {
        pShaSuite->freeFunc = &SHA3_freeDigest;
    }
#endif
    
    /* invalid context */
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* invalid key type */
    pKey->isPrivate = FALSE;
    status = edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
    
    /* unallocated key, use keyUnalloc */
    keyUnalloc.isPrivate = TRUE;
    status = edDSA_Sign(&keyUnalloc, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    keyUnalloc.pPubKey = pKeyBuffer;
    status = edDSA_Sign(&keyUnalloc, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
#ifndef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    keyUnalloc.pPubKey = NULL;
    keyUnalloc.pPrivKey = pKeyBuffer;
    status = edDSA_Sign(&keyUnalloc, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
#endif
    /* public key on curve is not validated in edDSA algorithm */
    
    pKey->isPrivate = FALSE;
    
    /******* edDSA_VerifySignature *******/
    
    /* null params */
    status = edDSA_VerifySignature(NULL, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_VerifySignature(pKey, NULL, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, NULL, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, NULL, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, NULL, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* wrong curve alg id */
    pKey->curve = curveX25519;
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_CURVE_ID_FOR_ALG);
    pKey->curve = curve;
    
    /* invalid sha suite */
    pShaSuite->allocFunc = NULL;
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);
    
    /* complete the shaSuite for future tests */
    if (curveEd25519 == curve)
    {
#ifndef __DISABLE_DIGICERT_SHA512__
        pShaSuite->allocFunc = &SHA512_allocDigest;
#else
        (void) curve;
#endif
    }
#ifdef __ENABLE_DIGICERT_SHA3__
    else  /* curveEd448 == curve */
    {
        pShaSuite->allocFunc = &SHA3_allocDigest;
    }
#endif
    
    /* invalid context */
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* invalid key type */
    pKey->isPrivate = TRUE;
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
    
    /* unallocaed key */
    keyUnalloc.isPrivate = FALSE;
    keyUnalloc.pPubKey = NULL;
    status = edDSA_VerifySignature(&keyUnalloc, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    /* invalid signature size */
    pKey->isPrivate = FALSE;
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 0, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 63, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 113, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    if (curveEd25519 == curve)
    { /* 114 is curve448's size */
        status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 114, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    else  /* curveEd448 == curve */
    {     /* 64 is curve25519's size */
        status = edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 64, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }

    /*
     public key or R of signature not on the curve are treates as a verify Failure and not an error. These are tested
     in the negativeVerify test vectors
     */

    /******* edDSA_initSignPreHash *******/

    pKey->isPrivate = TRUE;
    keyUnalloc.isPrivate = TRUE;
    
    status = edDSA_initSignPreHash(NULL, pKey, pShaSuite, pCtx, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_initSignPreHash(&signCtx, NULL, pShaSuite, pCtx, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = edDSA_initSignPreHash(&signCtx, pKey, NULL, pCtx, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = edDSA_initSignPreHash(&signCtx, pKey, pShaSuite, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = edDSA_initSignPreHash(&signCtx, pKey, pShaSuite, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = edDSA_initSignPreHash(&signCtx, &keyUnalloc, pShaSuite, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);

    pKey->isPrivate = FALSE;
    status = edDSA_initSignPreHash(&signCtx, pKey, pShaSuite, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);

    /******* edDSA_initVerify *******/

    keyUnalloc.isPrivate = FALSE;

    /* null params */
    status = edDSA_initVerify(NULL, pKey, pSignature, signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_initVerify(&verifyCtx, NULL, pSignature, signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_initVerify(&verifyCtx, pKey, NULL, signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, NULL, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, pShaSuite, FALSE, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invlalid ctx */
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, pShaSuite, FALSE, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* wrong curve alg id */
    pKey->curve = curveX25519;
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_CURVE_ID_FOR_ALG);
    pKey->curve = curve;
    
    /* invalid sha suite */
    pShaSuite->updateFunc = NULL;
    
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);
    
    /* complete the shaSuite for future tests */
    if (curveEd25519 == curve)
    {
#ifndef __DISABLE_DIGICERT_SHA512__
        pShaSuite->updateFunc = (BulkCtxUpdateFunc) &SHA512_updateDigest;
#else
        (void) curve;
#endif
    }
#ifdef __ENABLE_DIGICERT_SHA3__
    else  /* curveEd448 == curve */
    {
        pShaSuite->updateFunc = (BulkCtxUpdateFunc) &SHA3_updateDigest;
    }
#endif
    
    /* invalid key type */
    pKey->isPrivate = TRUE;
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
    
    /* unallocated key */
    status = edDSA_initVerify(&verifyCtx, &keyUnalloc, pSignature, signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    /* invalid signature size */
    pKey->isPrivate = FALSE;
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 0, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 63, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 113, pShaSuite, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    if (curveEd25519 == curve)
    { /* 114 is curve448's size */
        status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 114, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    else  /* curve448 == curve */
    {     /* 64 is curve25519's size */
        status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 64, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    
    /** test edDSA_update and edDSA_finalVerify while we have an un-init context **/
    
    status = edDSA_update(&verifyCtx, pMessage, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);
    
    status = edDSA_update(&signCtx, pMessage, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);

    status = edDSA_finalVerify(&verifyCtx, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);
    
    status = edDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);

    /*
     Complete a valid initialization for further tests, make sure S is
     in bounds, invalid S is a verify failure anyway, not an error.
     */
    if (curveEd25519 == curve)
    {
        pSignature[63] = 0x01;
        status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 64, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
                
        /* already initialized ctx */
        status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 64, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_ALREADY_INITIALIZED_CTX);
    }
    else  /* curve448 == curve */
    {
        pSignature[112] = 0x01;
        status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 114, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        /* already initialized ctx */
        status = edDSA_initVerify(&verifyCtx, pKey, pSignature, 114, pShaSuite, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_ALREADY_INITIALIZED_CTX);
    }
    
    pKey->isPrivate = TRUE;
    status = edDSA_initSignPreHash(&signCtx, pKey, pShaSuite, NULL, 0, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* already initialized ctx */    
    status = edDSA_initSignPreHash(&signCtx, pKey, pShaSuite, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_ALREADY_INITIALIZED_CTX);

    /******* edDSA_update ********/
    
    status = edDSA_update(NULL, pMessage, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_update(&verifyCtx, NULL, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_update(&signCtx, NULL, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* edDSA_finalSign ********/

    status = edDSA_finalSign(NULL, pSignature, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = edDSA_finalSign(&signCtx, NULL, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    status = edDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = edDSA_finalSign(&signCtx, pSignature, 63, &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    /******* edDSA_finalVerify ********/
    
    status = edDSA_finalVerify(NULL, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDSA_finalVerify(&verifyCtx, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* wrong curve alg id */
    verifyCtx.curve = curveX25519;
    status = edDSA_finalVerify(&verifyCtx, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_CURVE_ID_FOR_ALG);
    verifyCtx.curve = curve;
    
    /* call edDSA_finalVerify and edDSA_finalSign correctly so memory in the contexts are cleaned */
    
    status = edDSA_finalVerify(&verifyCtx, &verifyStatus, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    status = edDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

exit:
    
    if (NULL != pKey)
    {
        status = edECC_deleteKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) */


int ecc_edwards_dsa_unit_test_all()
{
    MSTATUS status;
    int retVal = 0;
    int i;
    
    BulkHashAlgo shaSuite = {0};
    
    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)
    
    /* Test edDSA on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 25519;
#endif
    
    /* First test with shaSuite having digest only APIs */
    shaSuite.digestFunc = (BulkCtxDigestFunc) &SHA512_completeDigest;
#ifdef __DEBUG_VECTORS__
    gShaSuite = 0;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p25519 + i, curveEd25519, &shaSuite);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* Next test with shaSuite having only EVP style APIs */
    shaSuite.allocFunc = &SHA512_allocDigest;
    shaSuite.initFunc = (BulkCtxInitFunc) &SHA512_initDigest;
    shaSuite.updateFunc = (BulkCtxUpdateFunc)&SHA512_updateDigest;
    shaSuite.finalFunc = (BulkCtxFinalFunc) &SHA512_finalDigest;
    shaSuite.freeFunc = &SHA512_freeDigest;
    shaSuite.digestFunc = NULL;
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gShaSuite = 1;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p25519 + i, curveEd25519, &shaSuite);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* test Error cases, one shaSuite is sufficient as we'll modify it for some tests anyway */
    retVal += testErrorCases(curveEd25519, &shaSuite);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)  */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_SHA3__)
    
    /* Test edDSA on curve448 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 448;
#endif
    
    /* First test with shaSuite having digest only APIs */
    shaSuite.allocFunc = NULL;
    shaSuite.initFunc = NULL;
    shaSuite.updateFunc = NULL;
    shaSuite.finalXOFFunc = NULL;
    shaSuite.freeFunc = NULL;
    shaSuite.digestXOFFunc = &shake256_digest;
#ifdef __DEBUG_VECTORS__
    gShaSuite = 0;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p448 + i, curveEd448, &shaSuite);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* Next test with shaSuite having only EVP style APIs */
    shaSuite.allocFunc = &SHA3_allocDigest;
    shaSuite.initFunc = &shake256_init;
    shaSuite.updateFunc = (BulkCtxUpdateFunc) &SHA3_updateDigest;
    shaSuite.finalXOFFunc = (BulkCtxFinalXOFFunc) &SHA3_finalDigest;
    shaSuite.freeFunc = &SHA3_freeDigest;
    shaSuite.digestXOFFunc = NULL;
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gShaSuite = 1;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p448 + i, curveEd448, &shaSuite);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* test Error cases, one shaSuite is sufficient as we'll modify it for some tests anyway */
    retVal += testErrorCases(curveEd448, &shaSuite);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_SHA3__) */
   
exit:
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    return retVal;
}
