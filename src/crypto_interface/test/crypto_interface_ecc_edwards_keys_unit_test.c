/*
 * crypto_interface_ecc_edwards_keys_unit_test.c
 *
 * test cases for crypto interface API, Edwards Curve Key generation related methods.
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
#include "../../crypto/ecc.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || \
    defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)

#define MAX_ENCODING_LEN 57 /* edDSA on curve 448 */

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
static ubyte gpNonce[MAX_ENCODING_LEN] = {0};  /* big enough for either curve */
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

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
#include "ecc_edwards_keys_data_25519_inc.h"
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
#include "ecc_edwards_keys_data_448_inc.h"
#endif


/********************************************************************************************/

/*
 Test EC_generateKeyPairEx against an expected key that was set with EC_setKeyParametersEx
 */
static int testGenerateKeyPair(ubyte4 curve, ECCKey *pExpectedKey)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 expectedKeyLen;
    sbyte4 compare;
    byteBoolean match = FALSE;
    ECCKey *pKey = NULL;
    
    status = EC_newKeyEx(curve, &pKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, pExpectedKey, &match);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (!match)
        UNITTEST_VECTOR_INT(__MOC_LINE__, 0, -1);  /* force error */
    
    /* look inside to make sure private key flag and private key also match */
    if (((edECCKey *)(pKey->pEdECCKey))->isPrivate != ((edECCKey *)(pExpectedKey->pEdECCKey))->isPrivate)
        UNITTEST_VECTOR_INT(__MOC_LINE__, 0, -1);  /* force error */

    status = EC_getElementByteStringLen(pExpectedKey, &expectedKeyLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(((edECCKey *)(pKey->pEdECCKey))->pPrivKey, ((edECCKey *)(pExpectedKey->pEdECCKey))->pPrivKey, expectedKeyLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    return retVal;
}

/*
 Tests EC_verifyKeyPairEx
 */
static int testValidateKeyPair(ECCKey *pPriv, ECCKey *pPub, ubyte4 expectedIntResult)
{
    MSTATUS status;
    int retVal = 0;
    byteBoolean verify;
    
    status = EC_verifyKeyPairEx(MOC_ECC(gpHwAccelCtx) pPriv, pPub, &verify);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verify, expectedIntResult);
    
    return retVal;
}

/*
 Tests EC_verifyPublicKeyEx
 */
static int testValidatePubKey(ECCKey *pKey, ubyte4 expectedIntResult)
{
    MSTATUS status;
    int retVal = 0;
    byteBoolean verify;
    
    status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) pKey, &verify);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verify, expectedIntResult);
    
    return retVal;
}

/*
 Tests EC_writePublicKeyToBuffer
 */
static int testGetPublicKey(ECCKey *pKey, ubyte *pExpectedResult)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    ubyte pPublicKey[MAX_ENCODING_LEN] = {0}; /* big enough for all curves/algos */
    ubyte4 keyLen;
    
    status = EC_getPointByteStringLenEx(pKey, &keyLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) pKey, pPublicKey, keyLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pPublicKey, pExpectedResult, keyLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    return retVal;
}


/* Tests EC_getKeyParametersAlloc, if pExpectedPriv that means we're just getting the public key */
static int testGetKeyParameters(ECCKey *pKey, ubyte *pExpectedPub, ubyte4 expectedPubLen, ubyte *pExpectedPriv, ubyte4 expectedPrivLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    MEccKeyTemplate template = {0};
    
    /* test getting just the pub whether the key is public or private */
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, &template, MOC_GET_PUBLIC_KEY_DATA);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, template.publicKeyLen, expectedPubLen);
    
    status = DIGI_MEMCMP(template.pPublicKey, pExpectedPub, template.publicKeyLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
    if (NULL != pExpectedPriv)
    {
        /* free the template and now get private key data */
        status = EC_freeKeyTemplate(pKey, &template);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, &template, MOC_GET_PRIVATE_KEY_DATA);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, template.publicKeyLen, expectedPubLen);
        
        status = DIGI_MEMCMP(template.pPublicKey, pExpectedPub, template.publicKeyLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, template.privateKeyLen, expectedPrivLen);
        
        status = DIGI_MEMCMP(template.pPrivateKey, pExpectedPriv, template.privateKeyLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    }
    
exit:
    
    /* free the template and now get private key data */
    status = EC_freeKeyTemplate(pKey, &template);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    return retVal;
}


/*
 tests EC_getCurveIdFromKey, EC_getElementByteStringLen, EC_getPointByteStringLenEx
       EC_newPublicKeyFromByteString, EC_cloneKeyEx, EC_equalKeyEx
 */
static int testKeyAuxMethods(ECCKey *pKey, ubyte *pPub, ubyte4 pubLen)
{
    MSTATUS status;
    int retVal = 0;
    byteBoolean res;
    sbyte4 compare;
    
    ubyte4 keyLen = 0;
    ubyte4 curveId = 0;
    ECCKey *pNewKey = NULL;
    
    /* test EC_getCurveIdFromKey */
    status = EC_getCurveIdFromKey(pKey, &curveId);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, curveId, pKey->curveId);

    /* test EC_getElementByteStringLen */
    status = EC_getElementByteStringLen(pKey, &keyLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, keyLen, pubLen);
    
    /* test EC_getPointByteStringLenEx */
    keyLen = 0;
    status = EC_getPointByteStringLenEx(pKey, &keyLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, keyLen, pubLen);
    
    /* test EC_newPublicKeyFromByteString */
    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pNewKey, pPub, pubLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* check via testing EC_equalKey */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pNewKey, pKey, &res);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    retVal += UNITTEST_TRUE(__MOC_LINE__, res);
    
    status = EC_deleteKeyEx(&pNewKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* test EC_cloneKeyEx */
    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) &pNewKey, pKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* check the public key via EC_equalKey */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pNewKey, pKey, &res);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    retVal += UNITTEST_TRUE(__MOC_LINE__, res);
    
    /* reach inside to validate the private key too */
    if (pNewKey->pCurve != pKey->pCurve)  /* both should be NULL */
         UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1);
    
    if (pNewKey->curveId != pKey->curveId)
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1);
    
    if (((edECCKey *) pNewKey->pEdECCKey)->isPrivate != ((edECCKey *) pKey->pEdECCKey)->isPrivate)
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1);
    
    /* even for a public key both should be all 0x00 */
    status = DIGI_MEMCMP(((edECCKey *) pNewKey->pEdECCKey)->pPrivKey, ((edECCKey *) pKey->pEdECCKey)->pPrivKey, keyLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:
    
    if (NULL != pNewKey)
    {
        status = EC_deleteKeyEx(&pNewKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int knownAnswerTest(TestVector *pTestVector, ubyte4 curve)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 keyLen;
    sbyte4 compare;
    
    ECCKey *pPrivKey = NULL;
    ECCKey *pPubKey = NULL;
    
    ubyte *pByteBufferInput1 = NULL;
    ubyte4 inputLen1 = 0;
    
    ubyte *pByteBufferInput2 = NULL;
    ubyte4 inputLen2 = 0;
    
    ubyte *pByteBufferInput3 = NULL;
    ubyte4 inputLen3 = 0;
    
    ubyte4 expectedIntResult = pTestVector->valid;
    TestVectorType type = pTestVector->type;
    
    ubyte pZeroBuffer[MAX_ENCODING_LEN] = {0}; /* big enough for either curve */
    
    if (NULL != pTestVector->pPrivKey)
        inputLen1 = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivKey, &pByteBufferInput1);
    if (NULL != pTestVector->pPubKey)
        inputLen2 = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPubKey, &pByteBufferInput2);
    if (NULL != pTestVector->pNonce)
        inputLen3 = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pByteBufferInput3);
    
    if (NULL != pByteBufferInput1 && NULL != pByteBufferInput2)
    {
        status = EC_newKeyEx(curve, &pPrivKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPrivKey, pByteBufferInput2, inputLen2, pByteBufferInput1, inputLen1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != pByteBufferInput2)
    {
        status = EC_newKeyEx(curve, &pPubKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPubKey, pByteBufferInput2, inputLen2, NULL, 0);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* all tests will have at least a public key */
    status = EC_getPointByteStringLenEx(pPubKey, &keyLen);
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
            
            retVal += testGenerateKeyPair(curve, pPrivKey);
            
            break;
            
        case getSetMethods:
            
            /*
             We already called edECC_setKeyParameters for the appropriate keys,
             just double check the memory was set correctly. First check the public key.
             */
            UNITTEST_VECTOR_INT(__MOC_LINE__, (int) ((edECCKey *) (pPubKey->pEdECCKey))->isPrivate, (int) FALSE);
            UNITTEST_VECTOR_INT(__MOC_LINE__, (int) pPubKey->curveId, (int) curve);
            
            status = DIGI_MEMCMP(((edECCKey *) (pPubKey->pEdECCKey))->pPrivKey, pZeroBuffer, keyLen, &compare);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
            
            UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
            
            status = DIGI_MEMCMP(((edECCKey *) (pPubKey->pEdECCKey))->pPubKey, pByteBufferInput2, keyLen, &compare);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
            
            UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
            
            /* test getting the public key */
            retVal += testGetPublicKey(pPubKey, pByteBufferInput2);
            
            /* test getting the public key as a key parameter */
            retVal += testGetKeyParameters(pPubKey, pByteBufferInput2, keyLen, NULL, 0);
            
            /* test rest of key auxiliary methods */
            retVal += testKeyAuxMethods(pPubKey, pByteBufferInput2, keyLen);
            
            /* if we had private key data also verify the private key */
            if (NULL != pPrivKey)
            {
                UNITTEST_VECTOR_INT(__MOC_LINE__, (int) ((edECCKey *) (pPrivKey->pEdECCKey))->isPrivate, (int) TRUE);
                UNITTEST_VECTOR_INT(__MOC_LINE__, (int) pPrivKey->curveId, (int) curve);
                
                status = DIGI_MEMCMP(((edECCKey *) (pPrivKey->pEdECCKey))->pPrivKey, pByteBufferInput1, keyLen, &compare);
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
                if (OK != status)
                    goto exit;
                
                UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
                
                status = DIGI_MEMCMP(((edECCKey *) (pPrivKey->pEdECCKey))->pPubKey, pByteBufferInput2, keyLen, &compare);
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
                if (OK != status)
                    goto exit;
                
                UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
                
                /* test getting the public key */
                retVal += testGetPublicKey(pPrivKey, pByteBufferInput2);
                
                /* test getting the all key parameters */
                retVal += testGetKeyParameters(pPrivKey, pByteBufferInput2, keyLen, pByteBufferInput1, keyLen);
                
                /* test rest of key auxiliary methods with a private key */
                retVal += testKeyAuxMethods(pPrivKey, pByteBufferInput2, keyLen);
            }
            
            break;
            
        case validateKey:
            
            /*
             test only as a private key if the data gave us a private key,
             since it may have valid public key part, but be an invalid private key.
             Only test public keys for DSA.
             */
            if (NULL != pPrivKey)
                retVal += testValidateKeyPair(pPrivKey, pPubKey, expectedIntResult);
            else if ( NULL != pPubKey)
                retVal += testValidatePubKey(pPubKey, expectedIntResult);
            
            break;
    }
    
exit:
    
    if (NULL != pPrivKey)
    {
        status = EC_deleteKeyEx(&pPrivKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubKey)
    {
        status = EC_deleteKeyEx(&pPubKey);
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


static int testErrorCases(ubyte4 curve)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 keyLen;
    
    ECCKey keyUnalloc = {0};
    ECCKey *pKey = NULL;
    
    ubyte pKeyBuffer[MAX_ENCODING_LEN] = {0}; /* big enough for either curve */
    ubyte pPubKeyBytes[MAX_ENCODING_LEN] = {0};
    
    byteBoolean verify = FALSE;
    MEccKeyTemplate template = {0};
    
    keyUnalloc.curveId = curve;
    
    /*
     Most error cases are tested in crypto_interface_ecc_unit_test.
     We only need to test cases specific to Edwards form keys like
     unallocated edwards keys and specific invalid lengths.
     */
    
    /* create a valid key for future tests, also get the keyLen */
    status = EC_newKeyEx(curve, &pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_getElementByteStringLen(pKey, &keyLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* EC_generateKeyPairEx *******/
    
    /* unallocated key */
    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, rngCallback, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* EC_setKeyParametersEx *******/

    /* unallocated key */
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pKeyBuffer, keyLen, pKeyBuffer, keyLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invlalid keyLen */
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pKeyBuffer, 0, pKeyBuffer, keyLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pKeyBuffer, keyLen - 1, pKeyBuffer, keyLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pKeyBuffer, keyLen + 1, pKeyBuffer, keyLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pKeyBuffer, keyLen, pKeyBuffer, keyLen - 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pKeyBuffer, keyLen, pKeyBuffer, keyLen + 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);

    /******* EC_verifyKeyPairEx *******/
    
    /* unallocated key */
    status = EC_verifyKeyPairEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pKey, &verify);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* EC_verifyPublickey *******/
    
    /* unallocated key */
    status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, &verify);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* EC_getPublicKey *******/
    
    /* Unallocated key */
    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pPubKeyBytes, keyLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* buffer too small */
    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) pKey, pPubKeyBytes, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);
    
    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) pKey, pPubKeyBytes, keyLen - 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);
    
    /******* EC_getKeyParametersAlloc *******/
    
    /* null params */
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) NULL, &template, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, NULL, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, &template, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /* Unallocated key */
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) &keyUnalloc, &template, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
exit:
    
    /* template should never have been allocated */
    if (NULL != template.pPrivateKey || NULL != template.pPublicKey)
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    
    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        
        /* call delete again to test unallocated key */
        status = EC_deleteKeyEx(&pKey);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    }
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || \
          defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__) */

int crypto_interface_ecc_edwards_keys_unit_test_all()
{
    int retVal = 0;
    
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) || !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    
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
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    
    /* Test edDH on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 25519;
    gTestType = 0;
#endif
    
    for (i = 0; i < COUNTOF(gTestVectorDH_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDH_p25519 + i, cid_EC_X25519);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(cid_EC_X25519);
    
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
        retVal += knownAnswerTest(gTestVectorDH_p448 + i, cid_EC_X448);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(cid_EC_X448);
    
#endif /* __ENABLE_DIGICERT_ECC_EDDH_448__ */
    
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)
    
    /* Test edDSA on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestType = 1;
#endif
    
    for (i = 0; i < COUNTOF(gTestVectorDSA_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDSA_p25519 + i, cid_EC_Ed25519);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(cid_EC_Ed25519);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)  */
    
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_SHA3__)

    /* Test edDSA on curve448 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestType = 1;
#endif
    
    for (i = 0; i < COUNTOF(gTestVectorDSA_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVectorDSA_p448 + i, cid_EC_Ed448);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* test Error cases */
    retVal += testErrorCases(cid_EC_Ed448);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_SHA3__) */

exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    
#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) || !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) */
    
    return retVal;
}
