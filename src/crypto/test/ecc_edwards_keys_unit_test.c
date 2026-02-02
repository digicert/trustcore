/*
 * ecc_edwards_keys_unit_test.c
 *
 *   unit test for ecc_edwards_keys.c
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
#include "../../crypto/ecc_edwards_keys.h"
#include "../../crypto/ecc_edwards.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || \
    defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;
static int gTestCurve = 0;
static int gTestType = 0;  /* 0 for DH, 1 for DSA one-shot sha suite, 2 for DSA evp sha suite */

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector_p%d and testType %d\n", gCurrentVector, gTestCurve, gTestType); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector_p%d and testType %d\n", gCurrentVector, gTestCurve, gTestType); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef enum TestVectorType {
    
    generateKey,
    getSetMethods,
    validateKey

} TestVectorType;

typedef struct TestVector
{
    char *pPrivKey;
    char *pPubKey;
    char *pNonce;
    ubyte4 valid;
    TestVectorType type;
    
} TestVector;

/* Global variables so the "fake RNG" callback method will have access as what to return */
static ubyte gpNonce[MOC_CURVE448_ENCODING_SIZE] = {0};  /* big enough for either curve */
static ubyte4 gNonceLen = 0;

/*
 A fake random number generator callBack method. It just write to the buffer
 the value of the global variable gpNonce. gpNonce is big enough for all curves,
 but we need to take into account the Endianness of the platforms pf_unit type.
 */
static sbyte4 rngCallback(void *rngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MSTATUS status = OK;
    
    (void) rngFunArg;
    
    if (length > gNonceLen) /* uh oh, force error */
    {
        UNITTEST_STATUS(__MOC_LINE__, -1);
        return -1;
    }
    
    status = DIGI_MEMCPY(pBuffer, gpNonce, length);
    UNITTEST_STATUS(__MOC_LINE__, status);
    
    return (sbyte4) status;
}

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


#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
#include "ecc_edwards_keys_data_25519_inc.h"
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
#include "ecc_edwards_keys_data_448_inc.h"
#endif


/********************************************************************************************/

/*
 Test edECC_generateKeyPair against an expected key that was set with edECC_setKeyParameters
 */
static int testGenerateKeyPair(edECCCurve curve, edECCKey *pExpectedKey, BulkHashAlgo *pShaSuite)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 expectedKeyLen;
    sbyte4 compare;
    byteBoolean match = FALSE;
    edECCKey *pKey = NULL;
    
    status = edECC_newKey(&pKey, curve, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edECC_generateKeyPair(pKey, rngCallback, NULL, pShaSuite, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edECC_equalKey(pKey, pExpectedKey, &match, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (!match)
        UNITTEST_VECTOR_INT(__MOC_LINE__, 0, -1);  /* force error */
    
    /* look inside to make sure private key flag and private key also match */
    if (pKey->isPrivate != pExpectedKey->isPrivate)
        UNITTEST_VECTOR_INT(__MOC_LINE__, 0, -1);  /* force error */

    status = edECC_getKeyLen(pExpectedKey, &expectedKeyLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pKey->pPrivKey, pExpectedKey->pPrivKey, expectedKeyLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pKey)
    {
        status = edECC_deleteKey(&pKey, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    return retVal;
}

/*
 Tests edECC_validateKey
 */
static int testValidateKey(edECCKey *pKey, ubyte4 expectedIntResult, BulkHashAlgo *pShaSuite)
{
    MSTATUS status;
    int retVal = 0;
    
    status = edECC_validateKey(pKey, pShaSuite, NULL);
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) status, expectedIntResult);

    return retVal;
}

/* Tests edECC_getPublicKey */
static int testGetPublicKey(edECCKey *pKey, ubyte *pExpectedResult, BulkHashAlgo *pShaSuite)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    ubyte pPublicKey[MOC_CURVE448_ENCODING_SIZE] = {0}; /* big enough for all curves/algos */
    ubyte4 keyLen;
    
    status = edECC_getKeyLen(pKey, &keyLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edECC_getPublicKey(pKey, pPublicKey, keyLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pPublicKey, pExpectedResult, keyLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:
    
    return retVal;
}

/* Tests edECC_getKeyParametersAlloc, if pExpectedPriv that means we're just getting the public key */
static int testGetKeyParameters(edECCKey *pKey, ubyte *pExpectedPub, ubyte4 expectedPubLen, ubyte *pExpectedPriv, ubyte4 expectedPrivLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    
    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;
    
    /* test getting just the pub whether the key is public or private */
    status = edECC_getKeyParametersAlloc(pKey, &pPub, &pubLen, NULL, NULL, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, pubLen, expectedPubLen);
    
    status = DIGI_MEMCMP(pPub, pExpectedPub, pubLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
    if (NULL != pExpectedPriv)
    {
        /* free pPub and now get both keys */
        status = DIGI_MEMSET(pPub, 0x00, pubLen);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        status = DIGI_FREE((void **) &pPub);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        /* test getting both keys */
        status = edECC_getKeyParametersAlloc(pKey, &pPub, &pubLen, &pPriv, &privLen, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, pubLen, expectedPubLen);
        
        status = DIGI_MEMCMP(pPub, pExpectedPub, pubLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, privLen, expectedPrivLen);
        
        status = DIGI_MEMCMP(pPriv, pExpectedPriv, privLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    }

exit:
    
    if (NULL != pPub)
    {
        status = DIGI_FREE((void **) &pPub);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPriv)
    {
        status = DIGI_FREE((void **) &pPriv);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


/* pShaSuite NULL means we're testing edECC_DH_... APIs */
static int knownAnswerTest(TestVector *pTestVector, edECCCurve curve, BulkHashAlgo *pShaSuite)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 keyLen;
    sbyte4 compare;
    
    edECCKey *pPrivKey = NULL;
    edECCKey *pPubKey = NULL;
    
    ubyte *pByteBufferInput1 = NULL;
    ubyte4 inputLen1 = 0;
    
    ubyte *pByteBufferInput2 = NULL;
    ubyte4 inputLen2 = 0;
    
    ubyte *pByteBufferInput3 = NULL;
    ubyte4 inputLen3 = 0;
    
    ubyte4 expectedIntResult = pTestVector->valid;
    TestVectorType type = pTestVector->type;
    
    ubyte pZeroBuffer[MOC_CURVE448_ENCODING_SIZE] = {0}; /* big enough for either curve */
    
    if (NULL != pTestVector->pPrivKey)
        inputLen1 = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivKey, &pByteBufferInput1);
    if (NULL != pTestVector->pPubKey)
        inputLen2 = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPubKey, &pByteBufferInput2);
    if (NULL != pTestVector->pNonce)
        inputLen3 = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pByteBufferInput3);
    
    if (NULL != pByteBufferInput1 && NULL != pByteBufferInput2)
    {
        status = edECC_newKey(&pPrivKey, curve, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = edECC_setKeyParameters(pPrivKey, pByteBufferInput2, inputLen2, pByteBufferInput1, inputLen1, NULL, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != pByteBufferInput2)
    {
        status = edECC_newKey(&pPubKey, curve, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = edECC_setKeyParameters(pPubKey, pByteBufferInput2, inputLen2, NULL, 0, NULL, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* all tests will have at least a public key */
    status = edECC_getKeyLen(pPubKey, &keyLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    switch(type)
    {
        case generateKey:
            
            /* First copy pByteBufferInput4, which is the nonce or random data, to gpNonce */
            gNonceLen = keyLen;
            status = DIGI_MEMCPY(gpNonce, pByteBufferInput3, keyLen);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
            
            retVal += testGenerateKeyPair(curve, pPrivKey, pShaSuite);
            
            break;
            
        case getSetMethods:
            
            /*
             We already called edECC_setKeyParameters for the appropriate keys,
             just double check the memory was set correctly. First check the public key.
             */
            UNITTEST_VECTOR_INT(__MOC_LINE__, (int) pPubKey->isPrivate, (int) FALSE);
            UNITTEST_VECTOR_INT(__MOC_LINE__, (int) pPubKey->curve, (int) curve);
            
            status = DIGI_MEMCMP(pPubKey->pPrivKey, pZeroBuffer, keyLen, &compare);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
            
            UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
            
            status = DIGI_MEMCMP(pPubKey->pPubKey, pByteBufferInput2, keyLen, &compare);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
            
            UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
            
            /* test getting the public key */
            retVal += testGetPublicKey(pPubKey, pByteBufferInput2, pShaSuite);
            
            /* test getting the public key as a key parameter */
            retVal += testGetKeyParameters(pPubKey, pByteBufferInput2, keyLen, NULL, 0);
            
            /* if we had private key data also verify the private key */
            if (NULL != pPrivKey)
            {
                UNITTEST_VECTOR_INT(__MOC_LINE__, (int) pPrivKey->isPrivate, (int) TRUE);
                UNITTEST_VECTOR_INT(__MOC_LINE__, (int) pPrivKey->curve, (int) curve);
                
                status = DIGI_MEMCMP(pPrivKey->pPrivKey, pByteBufferInput1, keyLen, &compare);
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
                if (OK != status)
                    goto exit;
                
                UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
                
                status = DIGI_MEMCMP(pPrivKey->pPubKey, pByteBufferInput2, keyLen, &compare);
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
                if (OK != status)
                    goto exit;
                
                UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
                
                /* test getting the public key */
                retVal += testGetPublicKey(pPrivKey, pByteBufferInput2, pShaSuite);
                
                /* test getting the all key parameters */
                retVal += testGetKeyParameters(pPrivKey, pByteBufferInput2, keyLen, pByteBufferInput1, keyLen);
            }
            break;
            
        case validateKey:
            
            /*
             test only as a private key if the data gave us a private key,
             since it may have valid public key part, but be an invalid private key.
             Only test public keys for DSA.
             */
            if (NULL != pPrivKey)
                retVal += testValidateKey(pPrivKey, expectedIntResult, pShaSuite);
            else if ( NULL != pPubKey && NULL != pShaSuite)
                retVal += testValidateKey(pPubKey, expectedIntResult, pShaSuite);
            
            break;
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
    if (NULL != pByteBufferInput1)
    {
        status = DIGI_FREE((void **) &pByteBufferInput1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pByteBufferInput2)
    {
        status = DIGI_FREE((void **) &pByteBufferInput2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pByteBufferInput3)
    {
        status = DIGI_FREE((void **) &pByteBufferInput3);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


/* pShaSuite NULL means we're testing edECC_DH_... APIs */
static int testErrorCases(edECCCurve curve, BulkHashAlgo *pShaSuite)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 keyLen;
    
    edECCKey keyUnalloc = {0};
    edECCKey *pKey = NULL;
    
    ubyte pKeyBuffer[MOC_CURVE448_ENCODING_SIZE] = {0}; /* big enough for either curve */
    ubyte pPubKeyBytes[MOC_CURVE448_ENCODING_SIZE] = {0};
    
    byteBoolean match = FALSE;
    
    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    
    keyUnalloc.curve = curve;
    
    /******* edECC_newKey *******/
    
    /* null param */
    status = edECC_newKey(NULL, curve, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid curve */
    status = edECC_newKey(&pKey, 4, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNSUPPORTED_CURVE);
    
    /* create a valid key for future tests, also get the keyLen */
    status = edECC_newKey(&pKey, curve, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edECC_getKeyLen(pKey, &keyLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* edECC_getKeyLen *******/
    
    /* null param */
    status = edECC_getKeyLen(NULL, &keyLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_getKeyLen(pKey, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid curve */
    pKey->curve = 4;
    status = edECC_getKeyLen(pKey, &keyLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNSUPPORTED_CURVE);
    pKey->curve = curve;
    
    /******* edECC_equalKey *******/
    
    /* null param */
    status = edECC_equalKey(NULL, pKey, &match, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_equalKey(pKey, NULL, &match, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_equalKey(pKey, pKey, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* edECC_cloneKey *******/
    
    /* null param */
    status = edECC_cloneKey(NULL, pKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_cloneKey(&pKey, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* edECC_generateKeyPair *******/
    
    /* null params */
    status = edECC_generateKeyPair(NULL, rngCallback, NULL, pShaSuite, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_generateKeyPair(pKey, NULL, NULL, pShaSuite, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* unallocated key */
    status = edECC_generateKeyPair(&keyUnalloc, rngCallback, NULL, pShaSuite, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    /* invlalid curve */
    pKey->curve = 4;
    status = edECC_generateKeyPair(pKey, rngCallback, NULL, pShaSuite, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNSUPPORTED_CURVE);
    pKey->curve = curve;
    
    /* invalid sha suite for edDSA algs */
    if (curveEd25519 == curve || curveEd448 == curve)
    {
        status = edECC_generateKeyPair(pKey, rngCallback, NULL, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
        
        /* invalid sha suite */
        pShaSuite->digestXOFFunc = NULL;
        pShaSuite->initFunc = NULL;
        
        status = edECC_generateKeyPair(pKey, rngCallback, NULL, pShaSuite, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);
        
        /*
         sufficient, will test other missing combos of sha methods with other APIs.
         complete the shaSuite for future tests
         */
        if (curveEd25519 == curve)
        {
#ifndef __DISABLE_DIGICERT_SHA512__
            pShaSuite->initFunc = (BulkCtxInitFunc) &SHA512_initDigest;
#else
            (void) curve;
#endif
        }
#ifdef __ENABLE_DIGICERT_SHA3__
        else  /* curveEd448 == curve */
        {
            pShaSuite->initFunc = &shake256_init;
        }
#endif
    }
    
    /******* edECC_setKeyParameters *******/
    
    /* null params, ok to re-use pKeyBuffer */
    status = edECC_setKeyParameters(NULL, pKeyBuffer, keyLen, pKeyBuffer, keyLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* ok for private key to be NULL or 0 length */
    
    status = edECC_setKeyParameters(pKey, NULL, keyLen, pKeyBuffer, keyLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_setKeyParameters(pKey, pKeyBuffer, keyLen, NULL, keyLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_setKeyParameters(pKey, NULL, 0, NULL, 0, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* unallocated key */
    status = edECC_setKeyParameters(&keyUnalloc, pKeyBuffer, keyLen, pKeyBuffer, keyLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    /* invlalid keyLen */
    status = edECC_setKeyParameters(pKey, pKeyBuffer, 0, pKeyBuffer, keyLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = edECC_setKeyParameters(pKey, pKeyBuffer, keyLen - 1, pKeyBuffer, keyLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = edECC_setKeyParameters(pKey, pKeyBuffer, keyLen + 1, pKeyBuffer, keyLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = edECC_setKeyParameters(pKey, pKeyBuffer, keyLen, pKeyBuffer, keyLen - 1, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = edECC_setKeyParameters(pKey, pKeyBuffer, keyLen, pKeyBuffer, keyLen + 1, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);

    /******* edECC_validateKey *******/
        
    /* null params */
    status = edECC_validateKey(NULL, pShaSuite, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* unallocated key */
    status = edECC_validateKey(&keyUnalloc, pShaSuite, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    /* invalid sha suite for edDSA algs */
    if (curveEd25519 == curve || curveEd448 == curve)
    {
        pKey->isPrivate = TRUE;
        status = edECC_validateKey(pKey, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
        
        /* invalid sha suite */
        if (curveEd25519 == curve)
            pShaSuite->finalFunc = NULL;
        else
            pShaSuite->finalXOFFunc = NULL;
        
        status = edECC_validateKey(pKey, pShaSuite, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);
        
        /* complete the shaSuite for future tests */
        if (curveEd25519 == curve)
        {
#ifndef __DISABLE_DIGICERT_SHA512__
            pShaSuite->finalFunc = (BulkCtxFinalFunc) &SHA512_finalDigest;
#else
            (void) curve;
#endif
        }
#ifdef __ENABLE_DIGICERT_SHA3__
        else  /* curveEd448 == curve */
        {
            pShaSuite->finalXOFFunc = (BulkCtxFinalXOFFunc) &SHA3_finalDigest;
        }
#endif
    }
    
    /******* edECC_getPublicKey *******/
    
    /* null params */
    status = edECC_getPublicKey(NULL, pPubKeyBytes, keyLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_getPublicKey(pKey, NULL, keyLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* Unallocated key */
    status = edECC_getPublicKey(&keyUnalloc, pPubKeyBytes, keyLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    /* buffer too small */
    status = edECC_getPublicKey(pKey, pPubKeyBytes, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);
    
    status = edECC_getPublicKey(pKey, pPubKeyBytes, keyLen - 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);
    
    /******* edECC_getKeyParametersAlloc *******/
    
    /* null params */
    status = edECC_getKeyParametersAlloc(NULL, &pPub, &pubLen, &pPriv, &privLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_getKeyParametersAlloc(pKey, NULL, &pubLen, &pPriv, &privLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edECC_getKeyParametersAlloc(pKey, &pPub, NULL, &pPriv, &privLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* pPriv and privLen are allowed to be NULL */
    
    /* Unallocated key */
    status = edECC_getKeyParametersAlloc(&keyUnalloc, &pPub, &pubLen, &pPriv, &privLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    keyUnalloc.isPrivate = TRUE;
    status = edECC_getKeyParametersAlloc(&keyUnalloc, &pPub, &pubLen, &pPriv, &privLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    
    /******* edECC_deleteKey *******/
    
    /* null param */
    status = edECC_deleteKey(NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
exit:
    
    /* pPub and pPriv should never have been allocated */
    if (NULL != pPub)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        DIGI_FREE((void **) &pPub);
    }
    if (NULL != pPriv)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        DIGI_FREE((void **) &pPriv);
    }
        
    if (NULL != pKey)
    {
        status = edECC_deleteKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        
        /* call delete again to test unallocated key */
        status = edECC_deleteKey(&pKey, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);
    }
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || \
          defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__) */

int ecc_edwards_keys_unit_test_all()
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
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    
    /* Test edDH on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 25519;
    gTestType = 0;
#endif
    
    for (i = 0; i < COUNTOF(gTestVectorDH_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDH_p25519 + i, curveX25519, NULL);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(curveX25519, NULL);
    
#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ */
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    
    /* Test edDH on curve448 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 448;
    gTestType = 0;
#endif
    
    for (i = 0; i < COUNTOF(gTestVectorDH_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDH_p448 + i, curveX448, NULL);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(curveX448, NULL);
    
#endif /* __ENABLE_DIGICERT_ECC_EDDH_448__ */
    
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)
    
    /* Test edDSA on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestType = 1;
#endif
    
    /* First test with shaSuite having digest only APIs */
    shaSuite.digestFunc = (BulkCtxDigestFunc) &SHA512_completeDigest;
    
    for (i = 0; i < COUNTOF(gTestVectorDSA_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDSA_p25519 + i, curveEd25519, &shaSuite);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* Next test with shaSuite having only EVP style APIs */
    shaSuite.allocFunc = &SHA512_allocDigest;
    shaSuite.initFunc = (BulkCtxInitFunc) &SHA512_initDigest;
    shaSuite.updateFunc = (BulkCtxUpdateFunc) &SHA512_updateDigest;
    shaSuite.finalFunc = (BulkCtxFinalFunc) &SHA512_finalDigest;
    shaSuite.freeFunc = &SHA512_freeDigest;
    shaSuite.digestFunc = NULL;

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestType = 2;
#endif
    
    for (i = 0; i < COUNTOF(gTestVectorDSA_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDSA_p25519 + i, curveEd25519, &shaSuite);
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
    gTestType = 1;
#endif
    
    /* First test with shaSuite having digest only APIs */
    shaSuite.allocFunc = NULL;
    shaSuite.initFunc = NULL;
    shaSuite.updateFunc = NULL;
    shaSuite.finalXOFFunc = NULL;
    shaSuite.freeFunc = NULL;
    shaSuite.digestXOFFunc = &shake256_digest;
    
    for (i = 0; i < COUNTOF(gTestVectorDSA_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDSA_p448 + i, curveEd448, &shaSuite);
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
    gTestType = 2;
#endif
    
    for (i = 0; i < COUNTOF(gTestVectorDSA_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDSA_p448 + i, curveEd448, &shaSuite);
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
