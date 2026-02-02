/*
 * crypto_interface_eddsa_test.c
 *
 * Expanded Unit test for EDDSA APIs
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
#include "../../crypto_interface/crypto_interface_ecc.h"
#include "../../crypto_interface/crypto_interface_eddsa.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
   !defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && \
   !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && \
   (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;
static int gTestCurve = 0;

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestCurve); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestCurve); retVal++;}

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

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
#include "../../crypto/test/ecc_edwards_dsa_data_25519_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
#include "../../crypto/test/ecc_edwards_dsa_data_448_inc.h"
#endif

static int testSign(ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pExpectedSig, ubyte4 expectedSigLen, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    ubyte pSignature[57*2] = {0}; /* big enough for either curve */
    ubyte4 signatureLen;
    
    /* Call with NULL pSignature to get the singatureLen */
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, pMessage, messageLen, NULL, 0, &signatureLen, preHash, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
    
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, preHash, pCtx, ctxLen, NULL);
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


static int testSignEVP(ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pExpectedSig, ubyte4 expectedSigLen, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    edDSA_CTX signCtx = {0};
    
    ubyte pSignature[57*2] = {0}; /* big enough for either curve */
    ubyte4 signatureLen;
    
    /* Call with NULL pSignature to get the singatureLen */
    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(&signCtx, pKey, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_INTERFACE_EdDSA_update(&signCtx, pMessage, messageLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_INTERFACE_EdDSA_finalSign(&signCtx, NULL, 0, &signatureLen, NULL);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);

    status = CRYPTO_INTERFACE_EdDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), &signatureLen, NULL);
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

static int testVerifyEVP(ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature, ubyte4 signatureLen, ubyte4 expectedVerifyStatus, 
                         byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 verifyStatus;
    
    edDSA_CTX verifyCtx = {0};
    
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, preHash, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /*
     CRYPTO_INTERFACE_EdDSA_update's message buffering is clearly relegated to the hash method used.
     The unit test for the hash method therefore has the responsibility for testing
     the buffering of pMessage into various size chunks. We will just make one straight call
     to CRYPTO_INTERFACE_EdDSA_update.
     */
    status = CRYPTO_INTERFACE_EdDSA_update(&verifyCtx, pMessage, messageLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_INTERFACE_EdDSA_finalVerify(&verifyCtx, &verifyStatus, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, verifyStatus, expectedVerifyStatus);
    
exit:
    
    return retVal;
}

static int testVerifyOneShot(ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature, ubyte4 signatureLen, ubyte4 expectedVerifyStatus, 
                             byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 verifyStatus;
    
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, preHash, pCtx, ctxLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, verifyStatus, expectedVerifyStatus);
    
exit:
    
    return retVal;
}

static int knownAnswerTest(TestVector *pTestVector, ubyte4 curve)
{
    MSTATUS status = OK;
    int retVal = 0;
    
    ECCKey *pPrivKey = NULL;
    ECCKey *pPubKey = NULL;
    
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
        status = CRYPTO_INTERFACE_EC_newKeyAux(curve, &pPrivKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = CRYPTO_INTERFACE_EC_setKeyParametersAux(pPrivKey, pPubBytes, pubLen, pPrivBytes, privLen);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != pPubBytes)
    {
        status = CRYPTO_INTERFACE_EC_newKeyAux(curve, &pPubKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = CRYPTO_INTERFACE_EC_setKeyParametersAux(pPubKey, pPubBytes, pubLen, NULL, 0);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* If there is a private key we test both sign and verify. Otherwise we test just verify */
    
    if (NULL != pPrivKey)
    {
        retVal += testSign(pPrivKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, pTestVector->preHash, pCtx, ctxLen);

        if (pTestVector->preHash)
        {
            retVal += testSignEVP(pPrivKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, pCtx, ctxLen);
        }
    }
    
    retVal += testVerifyOneShot(pPubKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, expectedVerifyStatus, pTestVector->preHash, pCtx, ctxLen);
    retVal += testVerifyEVP(pPubKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, expectedVerifyStatus, pTestVector->preHash, pCtx, ctxLen);

exit:
    
    if (NULL != pPrivKey)
    {
        status = CRYPTO_INTERFACE_EC_deleteKeyAux(&pPrivKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubKey)
    {
        status = CRYPTO_INTERFACE_EC_deleteKeyAux(&pPubKey);
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


static int testErrorCases(ubyte4 curve)
{
    MSTATUS status;
    int retVal = 0;
    
    ECCKey *pKey = NULL;
    
    ubyte pKeyBuffer[57] = {0};    /* big enough for either curve */
    
    ubyte pMessage[1] = {0};
    ubyte4 messageLen = 1;
    
    ubyte4 signatureLen = 0;
    
    ubyte pSignature[114] = {0};  /* big enough for either curve */
    ubyte pCtx[1] = {0}; 

    ubyte4 verifyStatus = 0;
    
    edDSA_CTX verifyCtx = {0};
    edDSA_CTX signCtx = {0};
        
    /* create a valid key for testing */
    
    status = CRYPTO_INTERFACE_EC_newKeyAux(curve, &pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* reach inside for testing, this needs to be changed if this test is extended for alternative implementations */
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = TRUE;
    
    /******* CRYPTO_INTERFACE_EdDSA_Sign *******/
    
    /* null params */
    status = CRYPTO_INTERFACE_EdDSA_Sign(NULL, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, NULL, messageLen, pSignature, sizeof(pSignature), &signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, pMessage, messageLen, NULL, sizeof(pSignature), &signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), NULL, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, FALSE, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
        
    /* invalid context */
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, FALSE, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* invalid key type */
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = FALSE;
    status = CRYPTO_INTERFACE_EdDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
        
    /* public key on curve is not validated in edDSA algorithm */
    
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = FALSE;
    
    /******* CRYPTO_INTERFACE_EdDSA_VerifySignature *******/
    
    /* null params */
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(NULL, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, NULL, messageLen, pSignature, signatureLen, &verifyStatus, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, NULL, signatureLen, &verifyStatus, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, FALSE, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
       
    /* invalid context */
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, FALSE, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* invalid key type */
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = TRUE;
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
        
    /* invalid signature size */
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = FALSE;
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 0, &verifyStatus, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 63, &verifyStatus, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 113, &verifyStatus, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    if (cid_EC_Ed25519 == curve)
    { /* 114 is curve448's size */
        status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 114, &verifyStatus, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    else  /* curveEd448 == curve */
    {     /* 64 is curve25519's size */
        status = CRYPTO_INTERFACE_EdDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, 64, &verifyStatus, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }

    /*
     public key or R of signature not on the curve are treates as a verify Failure and not an error. These are tested
     in the negativeVerify test vectors
     */

    /******* CRYPTO_INTERFACE_EdDSA_initSignPreHash *******/

    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = TRUE;
    
    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(NULL, pKey, pCtx, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(&signCtx, NULL, pCtx, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(&signCtx, pKey, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(&signCtx, pKey, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = FALSE;
    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(&signCtx, pKey, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);

    /******* CRYPTO_INTERFACE_EdDSA_initVerify *******/

    /* null params */
    status = CRYPTO_INTERFACE_EdDSA_initVerify(NULL, pKey, pSignature, signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, NULL, pSignature, signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, NULL, signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, FALSE, NULL, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invlalid ctx */
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, FALSE, pCtx, 256, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
       
    /* invalid key type */
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = TRUE;
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, signatureLen, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
        
    /* invalid signature size */
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = FALSE;
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 0, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 63, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 113, FALSE, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    if (cid_EC_Ed25519 == curve)
    { /* 114 is curve448's size */
        status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 114, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    else  /* curve448 == curve */
    {     /* 64 is curve25519's size */
        status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 64, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    
    /** test CRYPTO_INTERFACE_EdDSA_update and CRYPTO_INTERFACE_EdDSA_finalVerify while we have an un-init context **/
    
    status = CRYPTO_INTERFACE_EdDSA_update(&verifyCtx, pMessage, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);
    
    status = CRYPTO_INTERFACE_EdDSA_update(&signCtx, pMessage, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);

    status = CRYPTO_INTERFACE_EdDSA_finalVerify(&verifyCtx, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);
    
    status = CRYPTO_INTERFACE_EdDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_UNINITIALIZED_CTX);

    /*
     Complete a valid initialization for further tests, make sure S is
     in bounds, invalid S is a verify failure anyway, not an error.
     */
    if (cid_EC_Ed25519 == curve)
    {
        pSignature[63] = 0x01;
        status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 64, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
                
        /* already initialized ctx */
        status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 64, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_ALREADY_INITIALIZED_CTX);
    }
    else  /* cid_EC_Ed448 == curve */
    {
        pSignature[112] = 0x01;
        status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 114, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        /* already initialized ctx */
        status = CRYPTO_INTERFACE_EdDSA_initVerify(&verifyCtx, pKey, pSignature, 114, FALSE, NULL, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_ALREADY_INITIALIZED_CTX);
    }
    
    ((edECCKey *) (pKey->pEdECCKey))->isPrivate = TRUE;
    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(&signCtx, pKey, NULL, 0, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* already initialized ctx */    
    status = CRYPTO_INTERFACE_EdDSA_initSignPreHash(&signCtx, pKey, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_ALREADY_INITIALIZED_CTX);

    /******* CRYPTO_INTERFACE_EdDSA_update ********/
    
    status = CRYPTO_INTERFACE_EdDSA_update(NULL, pMessage, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_update(&verifyCtx, NULL, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_update(&signCtx, NULL, messageLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* CRYPTO_INTERFACE_EdDSA_finalSign ********/

    status = CRYPTO_INTERFACE_EdDSA_finalSign(NULL, pSignature, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = CRYPTO_INTERFACE_EdDSA_finalSign(&signCtx, NULL, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    status = CRYPTO_INTERFACE_EdDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = CRYPTO_INTERFACE_EdDSA_finalSign(&signCtx, pSignature, 63, &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    /******* CRYPTO_INTERFACE_EdDSA_finalVerify ********/
    
    status = CRYPTO_INTERFACE_EdDSA_finalVerify(NULL, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = CRYPTO_INTERFACE_EdDSA_finalVerify(&verifyCtx, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
        
    /* call CRYPTO_INTERFACE_EdDSA_finalVerify and CRYPTO_INTERFACE_EdDSA_finalSign correctly so memory in the contexts are cleaned */
    
    status = CRYPTO_INTERFACE_EdDSA_finalVerify(&verifyCtx, &verifyStatus, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    status = CRYPTO_INTERFACE_EdDSA_finalSign(&signCtx, pSignature, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

exit:
    
    if (NULL != pKey)
    {
        status = CRYPTO_INTERFACE_EC_deleteKeyAux(&pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif


int crypto_interface_eddsa_test_all()
{
    int retVal = 0;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
   !defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && \
   !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && \
   (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))    

    MSTATUS status;
    int i;

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
    
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
    
    /* Test edDSA on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 25519;
#endif
        
    for (i = 0; i < COUNTOF(gTestVector_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p25519 + i, cid_EC_Ed25519);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* test Error cases */
    retVal += testErrorCases(cid_EC_Ed25519);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)  */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    
    /* Test edDSA on curve448 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 448;
#endif
        
    for (i = 0; i < COUNTOF(gTestVector_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p448 + i, cid_EC_Ed448);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* test Error cases */
    retVal += testErrorCases(cid_EC_Ed448);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) */
   
exit:
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
#endif

    return retVal;
}
