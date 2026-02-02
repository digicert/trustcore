/*
 * crypto_interface_ecc_eg_unit_test.c
 *
 * Unit test for Elliptic Curve El-Gamal.
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
#include "../../crypto/primeec_eg.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__)

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

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

#define ECEG_TEST_MAX_UPDATE_CALLS 3                  /* sufficient to test all boundary cases */
#define ECEG_TEST_MAX_INDICES (MAX_UPDATE_CALLS+1)
#define ECEG_TEST_MAX_BLOCKS 4                        /* sufficient to test all boundary cases */
#define ECEG_TEST_MAX_PLAINTEXT_BYTES (ECEG_TEST_MAX_BLOCKS*66)      /* (recovered plaintext, 66 bytes/block for P521 */
#define ECEG_TEST_MAX_CIPHERTEXT_BYTES (ECEG_TEST_MAX_BLOCKS*4*66)   /* 66 bytes/block for P521 */

typedef struct TestVector
{
    char *pPrivateKey;
    char *pPublicKey;
    char *pNonce;
    char *pPlainText;
    char *pCipherText;
    ubyte numBlocks;
    
} TestVector;

#define ECEG_TEST_MAX_NONCE_BYTES 1179             /* for P521 encrypt error cases testing */
#define ECEG_PKCS_TEST_MAX_PLAINTEXT_BYTES 51      /* recovered plaintext, 51 bytes for P521 */
#define ECEG_PKCS_TEST_MAX_CIPHERTEXT_BYTES (4*66) /* 66 bytes for each of 4 coords for P521 */

typedef struct TestVectorPKCS
{
    char *pPrivateKey;
    char *pPublicKey;
    char *pNonce;
    char *pPlainText;
    char *pCipherText;
    
} TestVectorPKCS;

#ifdef __ENABLE_DIGICERT_ECC_P192__
#include "../../crypto/test/primeec_eg_data_192_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
#include "../../crypto/test/primeec_eg_data_224_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
#include "../../crypto/test/primeec_eg_data_256_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
#include "../../crypto/test/primeec_eg_data_384_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
#include "../../crypto/test/primeec_eg_data_521_inc.h"
#endif


/* Global variables so the "fake RNG" callback method will have access as what to return */
static ubyte gpNonce[ECEG_TEST_MAX_NONCE_BYTES] = {0};
static ubyte4 gNonceLen = 0;
static ubyte4 gNoncePosition = 0;


/*
 Method to copy a byte array representing a Big Endian integer to the gpNonce
 global variable in the correct format for creation of a PFE form point.
 */
static int copyRNGdata(ubyte *pRngData, ubyte4 rngDataLen, ubyte4 curveWords){
    
    int retVal = 0;
    int i;
    ubyte4 bytesPerValue = (ubyte4) curveWords * sizeof(pf_unit);
    ubyte *pPtr = pRngData + bytesPerValue - 1; /* Begin at the end of the first value */
    ubyte *pSubPtr = pRngData;
    ubyte4 dataLeft = rngDataLen;
    ubyte4 nonceLen = 0;
    ubyte *pNoncePtr = gpNonce + gNoncePosition;
    
#ifdef MOC_BIG_ENDIAN
    ubyte swap = 0x00;
    int j;
#endif
    
    /*
     copy the rng data to the global variable so the callback method has access to it.
     We assume each bytesPerValue bytes represents one integer (in Big Endian).
     The value passed in must be 0 padded correctly. Also note bytesPerValue
     may be different than the number of bytes per coordinate (and IS different on P521 as
     bytesPerValue is 72 but we only need 66 bytes to specify a coordinate).
     
     The value will be copied into a PFE directly (by the ECC code) so take into account
     word size and endianness.
     
     First do a sanity check on rngDataLen */
    
    if (0 != (rngDataLen % bytesPerValue) )
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1); /* Bad test vector, force error */
        goto exit;
    }
    
    /* First just reverse to Little Endian bytewise and zero pad the end */
    while(dataLeft)
    {
        /* The ECC code adds 1 to the raw result of the RNG, so subtract one here */
        /* in order to compensate, start with the last byte of each nonce value. */
        i = bytesPerValue - 1;
        pSubPtr[i]--;
        
        /* keep borrowing if needbe */
        while (0xFF == pSubPtr[i] && i > 0)
        {
            i--;
            pSubPtr[i]--;
        }
    
        for (i = 0; i < bytesPerValue; ++i)
        {
           pNoncePtr[nonceLen + i] = *pPtr--;
        }
        
        dataLeft -= bytesPerValue;
        nonceLen += bytesPerValue;
        pPtr += 2*bytesPerValue;   /* Move to the end of the next potential value */
        pSubPtr += bytesPerValue;
    }
    
    /* if platform stores a pf_unit Little Endian then we are done, else ... */
    
#ifdef MOC_BIG_ENDIAN
    
    /* reverse each pf_unit that will be formed from within the byte array gpNonce */
    
    for (i = 0; i < nonceLen; ++i)
    {
        for (j = 0; j < sizeof(pf_unit)/2; ++j)
        {
            swap = pNoncePtr[sizeof(pf_unit)*i + j];
            pNoncePtr[sizeof(pf_unit)*i + j] = pNoncePtr[sizeof(pf_unit)*i + sizeof(pf_unit) - j - 1];
            pNoncePtr[sizeof(pf_unit)*i + sizeof(pf_unit) - j - 1] = swap;
        }
    }
#endif
    
    /* set the global length */
    gNonceLen = gNoncePosition + nonceLen;
exit:
    
    return retVal;
}


/*
 A fake random number generator callBack method. It just write to the buffer
 the value of the global variable gpNonce. gpNonce is big enough for all curves,
 but we need to take into account the Endianness of the platforms pf_unit type.
 */
static sbyte4 rngCallback(void *rngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MSTATUS status = OK;
    
    (void) rngFunArg;
    
    if (length > gNonceLen - gNoncePosition) /* uh oh, force error */
        return -1;
    
    status = DIGI_MEMCPY(pBuffer, gpNonce + gNoncePosition, length);
    gNoncePosition += length;
    
    UNITTEST_STATUS(__MOC_LINE__, status);
    
    return (sbyte4) status;
}


/*
 A fake random number generator that only returns 0x00s. Used for error case testing
 */
static sbyte4 badRNGCallback(void *rngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MSTATUS status = OK;
    
    (void) rngFunArg;

    status = DIGI_MEMSET(pBuffer, 0x00, length);
    UNITTEST_STATUS(__MOC_LINE__, status);
    
    return (sbyte4) status;
}


static int testOneShotEncrypt(ECCKey *pPublicKey, ubyte *pPlainText, ubyte4 plainLen, ubyte *pExpectedCipher, ubyte4 expectedCipherLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    /* buffers to hold encrypt or decrypt results */
    ubyte *pResult = NULL;
    ubyte4 resultLen = 0;
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pPublicKey, &rngCallback, NULL, pPlainText, plainLen, &pResult, &resultLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, resultLen, expectedCipherLen);
    
    status = DIGI_MEMCMP(pResult, pExpectedCipher, expectedCipherLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:
    
    if (NULL != pResult)
    {
        status = DIGI_FREE((void **) &pResult);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}


static int testEvpEncrypt(ECCKey *pPublicKey, ubyte *pPlainText, ubyte *pExpectedCipher, ubyte4 *plainIndices, ubyte4* cipherIndices)
{
    MSTATUS status;
    int retVal = 0;
    int i;
    sbyte4 compare;
    
    ECEG_CTX ctx = {0};
    
    ubyte pResultBuffer[ECEG_TEST_MAX_CIPHERTEXT_BYTES] = {0};
    ubyte *pResultPtr = (ubyte *) pResultBuffer;
    ubyte4 bytesWritten = 0;
    ubyte4 totalBytesWritten = 0;
    
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pPublicKey, MOCANA_ECEG_ENCRYPT, &rngCallback, NULL, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    for (i = 0; i < ECEG_TEST_MAX_UPDATE_CALLS; ++i)
    {
        if (plainIndices[i+1] - plainIndices[i])
        {
            status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pPlainText + plainIndices[i], plainIndices[i+1] - plainIndices[i], pResultPtr, sizeof(pResultBuffer) - totalBytesWritten, &bytesWritten, NULL);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;
            
            UNITTEST_VECTOR_INT(__MOC_LINE__, bytesWritten, cipherIndices[i+1] - cipherIndices[i]);
        
            pResultPtr += bytesWritten;
            totalBytesWritten += bytesWritten;
        }
    }
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, totalBytesWritten, cipherIndices[ECEG_TEST_MAX_UPDATE_CALLS] - cipherIndices[0]);
    
    /* compare the result ciphertext to the expected */
    status = DIGI_MEMCMP(pResultBuffer, pExpectedCipher, totalBytesWritten, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    status = ECEG_final(MOC_ECC(gpHwAccelCtx) &ctx, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    return retVal;
}


static int testOneShotDecrypt(ECCKey *pPrivateKey, ubyte *pCipherText, ubyte4 cipherLen, ubyte *pExpectedPlain)
{
    MSTATUS status;
    int retVal = 0;
    int i;
    sbyte4 compare;
    ubyte4 coordLen = (pPrivateKey->pCurve->pPF->numBits+7)/8;
    ubyte4 numBlocks = cipherLen/(4*coordLen);
    ubyte *pPlainPtr = pExpectedPlain;
    
    /* buffers to hold encrypt or decrypt results */
    ubyte *pResult = NULL;
    ubyte *pResultPtr = NULL;
    ubyte4 resultLen = 0;
    
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pPrivateKey, pCipherText, cipherLen, &pResult, &resultLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, resultLen, numBlocks * coordLen);  /* not the same as expectedPlainLen */
    
    pResultPtr = pResult + MOCANA_ECEG_CTR_LEN;
    /* For each block, skip pass the counter of MOCANA_ECEG_CTR_LEN bytes (4) */
    for (i = 0; i < numBlocks; ++i)
    {
        status = DIGI_MEMCMP(pResultPtr, pPlainPtr, coordLen - MOCANA_ECEG_CTR_LEN, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
        
        pPlainPtr += coordLen - MOCANA_ECEG_CTR_LEN;
        pResultPtr += coordLen;
    }

exit:
    
    if (NULL != pResult)
    {
        status = DIGI_FREE((void **) &pResult);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


static int testEvpDecrypt(ECCKey *pPrivateKey, ubyte *pCipherText, ubyte *pExpectedPlain, ubyte4 *cipherIndices, ubyte4* plainIndices)
{
    MSTATUS status;
    int retVal = 0;
    int i;
    sbyte4 compare;
    ubyte4 coordLen = (pPrivateKey->pCurve->pPF->numBits+7)/8;
    ubyte4 numBlocks = (cipherIndices[ECEG_TEST_MAX_UPDATE_CALLS] - cipherIndices[0])/(4*coordLen);
    ubyte *pPlainPtr = pExpectedPlain;
    
    ECEG_CTX ctx = {0};
    
    ubyte pResultBuffer[ECEG_TEST_MAX_PLAINTEXT_BYTES] = {0};
    ubyte *pResultPtr = (ubyte *) pResultBuffer;
    ubyte4 bytesWritten = 0;
    ubyte4 totalBytesWritten = 0;
    
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pPrivateKey, MOCANA_ECEG_DECRYPT, NULL, NULL, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    for (i = 0; i < ECEG_TEST_MAX_UPDATE_CALLS; ++i)
    {
        if (cipherIndices[i+1] - cipherIndices[i])
        {
            status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pCipherText + cipherIndices[i], cipherIndices[i+1] - cipherIndices[i], pResultPtr, sizeof(pResultBuffer) - totalBytesWritten, &bytesWritten, NULL);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;
            
            UNITTEST_VECTOR_INT(__MOC_LINE__, bytesWritten, plainIndices[i+1] - plainIndices[i]);
            
            pResultPtr += bytesWritten;
            totalBytesWritten += bytesWritten;
        }
    }
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, totalBytesWritten, plainIndices[ECEG_TEST_MAX_UPDATE_CALLS] - plainIndices[0]);
    
    /* Reset pResultPtr and skip past the first counter */
    pResultPtr = (ubyte *) pResultBuffer + MOCANA_ECEG_CTR_LEN;
    
    /* For each block, skip pass the counter of MOCANA_ECEG_CTR_LEN bytes (4) */
    for (i = 0; i < numBlocks; ++i)
    {
        status = DIGI_MEMCMP(pResultPtr, pPlainPtr, coordLen - MOCANA_ECEG_CTR_LEN, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
        
        pPlainPtr += coordLen - MOCANA_ECEG_CTR_LEN;
        pResultPtr += coordLen;
    }
    
exit:
    
    status = ECEG_final(MOC_ECC(gpHwAccelCtx) &ctx, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    
    return retVal;
}


static int knownAnswerTest(TestVector *pTestVector, ubyte4 curveId, ubyte4 pIndices[][4][4], ubyte4 numEVPtests)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 coordLen = 0;
    int i;
    
    ECCKey *pPublicKey = NULL;
    ECCKey *pPrivateKey = NULL;
    
    ubyte *pPrivateKeyBytes = NULL;
    ubyte4 privLen = 0;
    
    ubyte *pPublicKeyBytes = NULL;
    ubyte4 pubLen = 0;
    
    ubyte *pNonce = NULL;
    ubyte4 nonceLen = 0;
    
    ubyte *pPlainText = NULL;
    ubyte4 plainLen = 0;

    ubyte *pCipherText = NULL;
    ubyte4 cipherLen = 0;
    
    if (NULL == pTestVector->pPrivateKey || NULL == pTestVector->pPublicKey || NULL == pTestVector->pNonce || NULL == pTestVector->pPlainText || NULL == pTestVector->pCipherText)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1); /* Bad test vector, force error */
        goto exit;
    }
    
    switch(curveId)
    {
        case cid_EC_P192:
            coordLen = 24;
            break;

        case cid_EC_P224:
            coordLen = 28;
            break;

        case cid_EC_P256:
            coordLen = 32;
            break;

        case cid_EC_P384:
            coordLen = 48;
            break;

        case cid_EC_P521:
            coordLen = 66;
            break;    
    }

    privLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivateKey, &pPrivateKeyBytes);
    pubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicKey, &pPublicKeyBytes);
    nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
    plainLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPlainText, &pPlainText);
    cipherLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pCipherText, &pCipherText);

    /* Set the keys */
    status = EC_newKeyEx(curveId, &pPublicKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPublicKey, pPublicKeyBytes, pubLen, NULL, 0);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_newKeyEx(curveId, &pPrivateKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPrivateKey, pPublicKeyBytes, pubLen, pPrivateKeyBytes, privLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* sanity check that the plainLen is a multiple of the correct block size */
    if (0 != plainLen % (coordLen - MOCANA_ECEG_CTR_LEN))
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1); /* bad test vector */
        goto exit;
    }

/* FIPS will call RNG for key validation so can't do encrypt vector tests, skip */
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    /* Set the nonce */
    gNoncePosition = 0;
    gNonceLen = 0;
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = copyRNGdata(pNonce, nonceLen, (coordLen + 7)/8);
#else
    status = copyRNGdata(pNonce, nonceLen, (coordLen + 3)/4);
#endif
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* Test Encrypt One shot API *******/
    
    retVal += testOneShotEncrypt(pPublicKey, pPlainText, plainLen, pCipherText, cipherLen);

    /******* Test Encrypt EVP API *******/
    
    for (i = 0; i < numEVPtests; ++i)
    {
        gNoncePosition = 0;
        retVal += testEvpEncrypt(pPublicKey, pPlainText, pCipherText, pIndices[i][0], pIndices[i][1]);
    }
#endif /*__ENABLE_DIGICERT_FIPS_MODULE__  */

    /******* Test Decrypt One shot API *******/
    
    retVal += testOneShotDecrypt(pPrivateKey, pCipherText, cipherLen, pPlainText);
    
    /******* Test Decrypt EVP API *******/
    
    for (i = 0; i < numEVPtests; ++i)
    {
        retVal += testEvpDecrypt(pPrivateKey, pCipherText, pPlainText, pIndices[i][2], pIndices[i][3]);
    }
    
exit:
    
    if (NULL != pPublicKey)
    {
        status = EC_deleteKeyEx(&pPublicKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPrivateKey)
    {
        status = EC_deleteKeyEx(&pPrivateKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPrivateKeyBytes)
    {
        status = DIGI_FREE((void **) &pPrivateKeyBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPublicKeyBytes)
    {
        status = DIGI_FREE((void **) &pPublicKeyBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPlainText)
    {
        status = DIGI_FREE((void **) &pPlainText);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pCipherText)
    {
        status = DIGI_FREE((void **) &pCipherText);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


static int knownAnswerTestPKCS(ubyte4 curveId, TestVectorPKCS *pTestVector)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    ubyte4 paddingLen;
    ubyte4 coordLen = 0;
    
    ubyte pGenCipherText[ECEG_PKCS_TEST_MAX_CIPHERTEXT_BYTES] = {0};
    ubyte pGenPlainText[ECEG_PKCS_TEST_MAX_PLAINTEXT_BYTES] = {0};
    
    ECCKey *pPriv = NULL;
    ECCKey *pPub = NULL;
    
    ubyte *pPrivateKey = NULL;
    ubyte4 privLen = 0;
    
    ubyte *pPublicKey = NULL;
    ubyte4 pubLen = 0;
    
    ubyte *pNonce = NULL;
    ubyte4 nonceLen = 0;
    
    ubyte *pPlainText = NULL;
    ubyte4 plainLen = 0;
    
    ubyte *pCipherText = NULL;
    ubyte4 cipherLen = 0;
    
    if (NULL == pTestVector->pPrivateKey || NULL == pTestVector->pPublicKey || NULL == pTestVector->pNonce || NULL == pTestVector->pPlainText || NULL == pTestVector->pCipherText)
    {
        UNITTEST_VECTOR_STATUS(gCurrentVector, -1); /* Bad test vector, force error */
        goto exit;
    }
    
    switch(curveId)
    {
        case cid_EC_P192:
            coordLen = 24;
            break;

        case cid_EC_P224:
            coordLen = 28;
            break;

        case cid_EC_P256:
            coordLen = 32;
            break;

        case cid_EC_P384:
            coordLen = 48;
            break;

        case cid_EC_P521:
            coordLen = 66;
            break;    
    }

    privLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivateKey, &pPrivateKey);
    pubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicKey, &pPublicKey);
    nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
    plainLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPlainText, &pPlainText);
    cipherLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pCipherText, &pCipherText);
    
/* FIPS will call RNG for key validation so can't do encrypt vector tests, skip */
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__

    /* padding nonce just gets copied */
#ifdef __ENABLE_DIGICERT_64_BIT__
    paddingLen = nonceLen - ((coordLen + 7)/8) * 8; /* last (pEC->pPF->n) * sizeof(pf_unit) is the ElGamal nonce */
#else
    paddingLen = nonceLen - ((coordLen + 3)/4) * 4;
#endif
    
    status = DIGI_MEMCPY(gpNonce, pNonce, paddingLen);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    gNoncePosition = paddingLen;
    gNonceLen = paddingLen;
    
    /* Set the nonce */
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = copyRNGdata(pNonce + paddingLen, nonceLen - paddingLen, (coordLen + 7)/8 );
#else
    status = copyRNGdata(pNonce + paddingLen, nonceLen - paddingLen, (coordLen + 3)/4 );
#endif
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;


    /* reset the noncePosition before each encrypt test */
    gNoncePosition = 0;
    
    /* Set the keys */
    status = EC_newKeyEx(curveId, &pPub);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPub, pPublicKey, pubLen, NULL, 0);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    status = EC_newKeyEx(curveId, &pPriv);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPriv, pPublicKey, pubLen, pPrivateKey, privLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#ifndef __ENABLE_DIGICERT_FIPS_MODULE__    
    /******* Test Encrypt *******/
    
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pPub, rngCallback, NULL, pPlainText, plainLen, pGenCipherText, NULL);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if(OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pGenCipherText, pCipherText, cipherLen, &compare);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    
    UNITTEST_VECTOR_INT(gCurrentVector, compare, 0);
#endif

    /******* Test Decrypt *******/
    
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pPriv, pCipherText, cipherLen, pGenPlainText, NULL);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if(OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pGenPlainText, pPlainText, plainLen, &compare);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    
    UNITTEST_VECTOR_INT(gCurrentVector, compare, 0);
    
exit:
    
    if (NULL != pPub)
    {
        status = EC_deleteKeyEx(&pPub);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pPriv)
    {
        status = EC_deleteKeyEx(&pPriv);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    
    if (NULL != pPrivateKey)
    {
        status = DIGI_FREE((void **) &pPrivateKey);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pPublicKey)
    {
        status = DIGI_FREE((void **) &pPublicKey);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pPlainText)
    {
        status = DIGI_FREE((void **) &pPlainText);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pCipherText)
    {
        status = DIGI_FREE((void **) &pCipherText);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    
    return retVal;
}


static int testErrorCases(ubyte4 curveId, ubyte4 curveBits)
{
    MSTATUS status;
    int retVal = 0;
    int plainBlockSize = (curveBits+7)/8 - MOCANA_ECEG_CTR_LEN;
    int cipherBlockSize = 4*((curveBits+7)/8);
    
    ECEG_CTX ctx = {0};
    
    ECCKey *pKey = NULL;
    ECCKey unallocKey = {0};

    ubyte pInput[62] = {0}; /* big enough for all curves */
    ubyte pResultBuffer[1] = {0}; /* does not need to be valid */
    
    ubyte *pResult = NULL;
    ubyte4 resultLen = 0;
    
    /* Allocate pKey */
    status = EC_newKeyEx(curveId, &pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* ECEG_encrypt *******/
    
    /* Null params */
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) NULL, &rngCallback, NULL, pInput, plainBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, NULL, NULL, pInput, plainBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, &rngCallback, NULL, NULL, plainBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, &rngCallback, NULL, pInput, plainBlockSize, NULL, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, &rngCallback, NULL, pInput, plainBlockSize, &pResult, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* bad key */
    pKey->privateKey = TRUE;
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, &rngCallback, NULL, pInput, plainBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_KEY_TYPE);
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) &unallocKey, &rngCallback, NULL, pInput, plainBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNALLOCATED_KEY);
    
    /* bad inputLen */
    pKey->privateKey = FALSE;
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, &rngCallback, NULL, pInput, 0, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_INPUT_LEN);
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, &rngCallback, NULL, pInput, plainBlockSize - 1, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_INPUT_LEN);
    
    status = ECEG_encrypt(MOC_ECC(gpHwAccelCtx) pKey, &rngCallback, NULL, pInput, plainBlockSize + 1, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_INPUT_LEN);
    
    /******* ECEG_decrypt *******/
    
    /* Null params */
    pKey->privateKey = TRUE;
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) NULL, pInput, cipherBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pKey, NULL, cipherBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pKey, pInput, cipherBlockSize, NULL, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pKey, pInput, cipherBlockSize, &pResult, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* bad key */
    pKey->privateKey = FALSE;
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pKey, pInput, cipherBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_KEY_TYPE);
    
    unallocKey.privateKey = TRUE;
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) &unallocKey, pInput, cipherBlockSize, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNALLOCATED_KEY);
    
    /* bad inputLen (no curve has 0, 95, or 265 ciphertext blocksize) */
    pKey->privateKey = TRUE;
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pKey, pInput, 0, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_INPUT_LEN);
    
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pKey, pInput, cipherBlockSize - 1, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_INPUT_LEN);
    
    status = ECEG_decrypt(MOC_ECC(gpHwAccelCtx) pKey, pInput, cipherBlockSize + 1, &pResult, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_INPUT_LEN);
    
    /******* ECEG_init *******/
    
    /* Null params */
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) NULL, pKey, MOCANA_ECEG_ENCRYPT, &rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, NULL, MOCANA_ECEG_ENCRYPT, &rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pKey, MOCANA_ECEG_ENCRYPT, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) NULL, pKey, MOCANA_ECEG_DECRYPT, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, NULL, MOCANA_ECEG_DECRYPT, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* bad direction */
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pKey, 2, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /* bad key */
    pKey->privateKey = FALSE;
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pKey, MOCANA_ECEG_DECRYPT, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_KEY_TYPE);
    
    pKey->privateKey = TRUE;
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pKey, MOCANA_ECEG_ENCRYPT, &rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_KEY_TYPE);
    
    unallocKey.privateKey = FALSE;
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, &unallocKey, MOCANA_ECEG_ENCRYPT, &rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNALLOCATED_KEY);
    
    unallocKey.privateKey = TRUE;
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, &unallocKey, MOCANA_ECEG_DECRYPT, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNALLOCATED_KEY);
    
    /* test update and final Now on uninitialized ctx */
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pInput, plainBlockSize, pResultBuffer, cipherBlockSize, &resultLen, NULL);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNINITIALIZED_CTX);
#endif
    
    status = ECEG_final(MOC_ECC(gpHwAccelCtx) &ctx, NULL);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNINITIALIZED_CTX);
#endif
    
    /* correctly init for further tests (rng doesn't matter) */
    pKey->privateKey = FALSE;
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pKey, MOCANA_ECEG_ENCRYPT, &badRNGCallback, NULL, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* already initialized */
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pKey, MOCANA_ECEG_ENCRYPT, &rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_ALREADY_INITIALIZED_CTX);
    
    status = ECEG_init(MOC_ECC(gpHwAccelCtx) &ctx, pKey, MOCANA_ECEG_DECRYPT, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_ALREADY_INITIALIZED_CTX);
    
    /******* ECEG_update *******/
    
    /* Null params */
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) NULL, pInput, plainBlockSize, pResultBuffer, cipherBlockSize, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, NULL, plainBlockSize, pResultBuffer, cipherBlockSize, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pInput, plainBlockSize, NULL, cipherBlockSize, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pInput, plainBlockSize, pResultBuffer, cipherBlockSize, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* result buffer too small */
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pInput, plainBlockSize, pResultBuffer, 0, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pInput, plainBlockSize, pResultBuffer, cipherBlockSize - 1, &resultLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    /* Test update with no data, which is an ok no-op (but not tested above) */
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, NULL, 0, NULL, 0, &resultLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /* Properly call update with one byte for tests of ECEG_final */
    status = ECEG_update(MOC_ECC(gpHwAccelCtx) &ctx, pInput, 1, NULL, 0, &resultLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* ECEG_final *******/
    
    /* Null param */
    status = ECEG_final(MOC_ECC(gpHwAccelCtx) NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invlalid input len */
    status = ECEG_final(MOC_ECC(gpHwAccelCtx) &ctx, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_INPUT_LEN);
    
exit:
    
    /* pResult should have never been allocated */
    if (NULL != pResult)
    {
        retVal += UNITTEST_INT(__MOC_LINE__, 0, -1); /* force error */
        status = DIGI_FREE((void **) &pResult);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (ctx.isInitialized)
    {
        /* Force final to properly clean */
        ctx.position = 0;
        status = ECEG_final(MOC_ECC(gpHwAccelCtx) &ctx, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
        
    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int testErrorCasesPKCS(ubyte4 curveId, ubyte4 curveBits)
{
    MSTATUS status;
    int retVal = 0;
    
    /* Buffers big enough for all curves */
    ubyte pPlain[ECEG_PKCS_TEST_MAX_PLAINTEXT_BYTES] = {0};
    ubyte pCipher[ECEG_PKCS_TEST_MAX_CIPHERTEXT_BYTES] = {0};

    ubyte4 plainLen = ((curveBits+7)/8) - 15; /* minus 4 byte counter and 11 pkcs v1.5 padding bytes */
    ubyte4 cipherLen = 4*((curveBits+7)/8);
    
    ECCKey *pKey = NULL;
    ECCKey unallocKey = {0};
    
    /* create dummy key */
    
    /* Allocate pKey */
    status = EC_newKeyEx(curveId, &pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* ECEG_encryptPKCSv1p5 *******/
    
    /* null params */
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) NULL, rngCallback, NULL, pPlain, plainLen, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, NULL, NULL, pPlain, plainLen, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, NULL, plainLen, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pPlain, plainLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid key type */
    pKey->privateKey = TRUE;
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pPlain, plainLen, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_KEY_TYPE);
    pKey->privateKey = FALSE;
    
    /* unalloc key */
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) &unallocKey, rngCallback, NULL, pPlain, plainLen, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNALLOCATED_KEY);

    /* invalid plaintext len */
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pPlain, 0, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_PLAINTEXT_LEN);
    
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pPlain, plainLen + 1, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_PLAINTEXT_LEN);
    
    /* invalid rng */
    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, badRNGCallback, NULL, pPlain, plainLen, pCipher, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_PRNG);
    
    /******* ECEG_decryptPKCSv1p5 *******/
    
    /* null params */
    pKey->privateKey = TRUE;
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) NULL, pCipher, cipherLen, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, NULL, cipherLen, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, pCipher, cipherLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid key type */
    pKey->privateKey = FALSE;
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, pCipher, cipherLen, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_KEY_TYPE);
    pKey->privateKey = TRUE;
    
    /* unalloc key */
    unallocKey.privateKey = TRUE;
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) &unallocKey, pCipher, cipherLen, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_UNALLOCATED_KEY);
    
    /* invalid cipher len */
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, pCipher, 0, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_CIPHERTEXT_LEN);
    
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, pCipher, cipherLen - 1, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_CIPHERTEXT_LEN);
    
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, pCipher, cipherLen + 1, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECEG_INVALID_CIPHERTEXT_LEN);
    
    /* first half of ciphertext (0,0), not on curve */
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pKey, pCipher, cipherLen, pPlain, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_DIFFERENT_CURVE);
    
exit:
    
    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


/* Test additional error cases specific to ECEG_encryptPKCSv1p5 */
static int testErrorCasesEnc(ubyte4 curveId, TestVectorPKCS *pTestVector, MSTATUS expectedStatus)
{
    MSTATUS status;
    int retVal = 0;
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    ubyte4 paddingLen;
    ubyte4 coordLen = 0;
    
    ubyte pGenCipherText[ECEG_TEST_MAX_CIPHERTEXT_BYTES] = {0};
    
    ubyte *pPublicKey = NULL;
    ubyte4 pubLen = 0;
    
    ubyte *pNonce = NULL;
    ubyte4 nonceLen = 0;
    
    ubyte *pPlainText = NULL;
    ubyte4 plainLen = 0;
    
    ECCKey *pPub = NULL;
    
    if (NULL == pTestVector->pPublicKey || NULL == pTestVector->pNonce || NULL == pTestVector->pPlainText)
    {
        UNITTEST_VECTOR_STATUS(gCurrentVector, -1); /* Bad test vector, force error */
        goto exit;
    }

    switch(curveId)
    {
        case cid_EC_P192:
            coordLen = 24;
            break;

        case cid_EC_P224:
            coordLen = 28;
            break;

        case cid_EC_P256:
            coordLen = 32;
            break;

        case cid_EC_P384:
            coordLen = 48;
            break;

        case cid_EC_P521:
            coordLen = 66;
            break;    
    }
    
    pubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicKey, &pPublicKey);
    nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
    plainLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPlainText, &pPlainText);
    
    /* padding nonce just gets copied */
    
    if (-1 == expectedStatus) /* our error code from the rng callback */
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        paddingLen = nonceLen - 16*((coordLen + 7)/8)*8; /* last 16*(pEC->pPF->n) * sizeof(pf_unit) is the ElGamal nonce */
#else
        paddingLen = nonceLen - 16*((coordLen + 3)/4)*4;
#endif
    }
    else
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        paddingLen = nonceLen - ((coordLen + 7)/8)*8; /* last (pEC->pPF->n) * sizeof(pf_unit) is the ElGamal nonce */
#else
        paddingLen = nonceLen - ((coordLen + 3)/4)*4;
#endif
    }
    
    status = DIGI_MEMCPY(gpNonce, pNonce, paddingLen);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    gNoncePosition = paddingLen;
    gNonceLen = paddingLen;
    
    /* Set the nonce */
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = copyRNGdata(pNonce + paddingLen, nonceLen - paddingLen, (coordLen + 7)/8 );
#else
    status = copyRNGdata(pNonce + paddingLen, nonceLen - paddingLen, (coordLen + 3)/4 );
#endif
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* reset the noncePosition before each encrypt test */
    gNoncePosition = 0;
    
    /* Allocate pPub */
    status = EC_newKeyEx(curveId, &pPub);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPub, pPublicKey, pubLen, NULL, 0);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECEG_encryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pPub, rngCallback, NULL, pPlainText, plainLen, pGenCipherText, NULL);
    UNITTEST_VECTOR_INT(gCurrentVector, status, expectedStatus);

exit:
    
    if (NULL != pPublicKey)
    {
        status = DIGI_FREE((void **) &pPublicKey);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pPlainText)
    {
        status = DIGI_FREE((void **) &pPlainText);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    
    if (NULL != pPub)
    {
        status = EC_deleteKeyEx(&pPub);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */
    return retVal;
}


/* Test additional error cases specific to ECEG_decryptPKCSv1p5 */
static int testErrorCasesDec(ubyte4 curveId, TestVectorPKCS *pTestVector, MSTATUS expectedStatus)
{
    MSTATUS status;
    int retVal = 0;
    
    ubyte pGenPlainText[ECEG_TEST_MAX_PLAINTEXT_BYTES] = {0};
    
    ubyte *pPrivateKey = NULL;
    ubyte4 privLen = 0;

    ubyte *pPublicKey = NULL;
    ubyte4 pubLen = 0;
    
    ubyte *pCipherText = NULL;
    ubyte4 cipherLen = 0;
    
    ECCKey *pPriv = NULL;
    
    if (NULL == pTestVector->pPrivateKey || NULL == pTestVector->pPublicKey || NULL == pTestVector->pCipherText)
    {
        UNITTEST_VECTOR_STATUS(gCurrentVector, -1); /* Bad test vector, force error */
        goto exit;
    }
    
    pubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicKey, &pPublicKey);
    privLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivateKey, &pPrivateKey);
    cipherLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pCipherText, &pCipherText);
    
    /* Allocate pPub */
    status = EC_newKeyEx(curveId, &pPriv);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPriv, pPublicKey, pubLen, pPrivateKey, privLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = ECEG_decryptPKCSv1p5(MOC_ECC(gpHwAccelCtx) pPriv, pCipherText, cipherLen, pGenPlainText, NULL);
    UNITTEST_VECTOR_INT(gCurrentVector, status, expectedStatus);
    
exit:
    
    if (NULL != pPublicKey)
    {
        status = DIGI_FREE((void **) &pPublicKey);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pPrivateKey)
    {
        status = DIGI_FREE((void **) &pPrivateKey);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    if (NULL != pCipherText)
    {
        status = DIGI_FREE((void **) &pCipherText);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    
    if (NULL != pPriv)
    {
        status = EC_deleteKeyEx(&pPriv);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__) */

int crypto_interface_ecc_eg_test_all()
{
    int retVal = 0;

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    int i;
    MSTATUS status;

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

#ifdef __ENABLE_DIGICERT_ECC_P192__
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 192;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p192); ++i)
    {
        switch (gTestVector_p192[i].numBlocks)
        {
            case 1:
                retVal += knownAnswerTest(gTestVector_p192+i, cid_EC_P192, gpIndicesOneBlock_p192, COUNTOF(gpIndicesOneBlock_p192));
                break;
                
            case 2:
                retVal += knownAnswerTest(gTestVector_p192+i, cid_EC_P192, gpIndicesTwoBlocks_p192, COUNTOF(gpIndicesTwoBlocks_p192));
                break;
                
            case 4:
                retVal += knownAnswerTest(gTestVector_p192+i, cid_EC_P192, gpIndicesFourBlocks_p192, COUNTOF(gpIndicesFourBlocks_p192));
                break;
        }
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(cid_EC_P192, 192);
    
    /* Test the pkcs #1 v1.5 padding API's */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 192;
#endif
    for (i = 0; i < sizeof(gTestVector_p192PKCS)/sizeof(gTestVector_p192PKCS[0]); ++i)
    {
        retVal += knownAnswerTestPKCS(cid_EC_P192, gTestVector_p192PKCS+i);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCasesPKCS(cid_EC_P192, 192);
    
#endif /* __ENABLE_DIGICERT_ECC_P192__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P224__
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 224;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p224); ++i)
    {
        switch (gTestVector_p224[i].numBlocks)
        {
            case 1:
                retVal += knownAnswerTest(gTestVector_p224+i, cid_EC_P224, gpIndicesOneBlock_p224, COUNTOF(gpIndicesOneBlock_p224));
                break;
                
            case 2:
                retVal += knownAnswerTest(gTestVector_p224+i, cid_EC_P224, gpIndicesTwoBlocks_p224, COUNTOF(gpIndicesTwoBlocks_p224));
                break;
                
            case 4:
                retVal += knownAnswerTest(gTestVector_p224+i, cid_EC_P224, gpIndicesFourBlocks_p224, COUNTOF(gpIndicesFourBlocks_p224));
                break;
        }
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(cid_EC_P224, 224);
    
    /* Test the pkcs #1 v1.5 padding API's */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 224;
#endif
    for (i = 0; i < sizeof(gTestVector_p224PKCS)/sizeof(gTestVector_p224PKCS[0]); ++i)
    {
        retVal += knownAnswerTestPKCS(cid_EC_P224, gTestVector_p224PKCS+i);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCasesPKCS(cid_EC_P224, 224);
    
#endif /* __DISABLE_DIGICERT_ECC_P224__  */

#if !defined(__DISABLE_DIGICERT_ECC_P256__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 256;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p256); ++i)
    {
        switch (gTestVector_p256[i].numBlocks)
        {
            case 1:
                retVal += knownAnswerTest(gTestVector_p256+i, cid_EC_P256, gpIndicesOneBlock_p256, COUNTOF(gpIndicesOneBlock_p256));
                break;
                
            case 2:
                retVal += knownAnswerTest(gTestVector_p256+i, cid_EC_P256, gpIndicesTwoBlocks_p256, COUNTOF(gpIndicesTwoBlocks_p256));
                break;
                
            case 4:
                retVal += knownAnswerTest(gTestVector_p256+i, cid_EC_P256, gpIndicesFourBlocks_p256, COUNTOF(gpIndicesFourBlocks_p256));
                break;
        }
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(cid_EC_P256, 256);
    
    /* Test the pkcs #1 v1.5 padding API's */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 256;
#endif
    for (i = 0; i < sizeof(gTestVector_p256PKCS)/sizeof(gTestVector_p256PKCS[0]); ++i)
    {
        retVal += knownAnswerTestPKCS(cid_EC_P256, gTestVector_p256PKCS+i);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCasesPKCS(cid_EC_P256, 256);
    
#endif /* __DISABLE_DIGICERT_ECC_P256__ && !__ENABLE_DIGICERT_ECC_P256_OPERATOR__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P384__
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 384;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p384); ++i)
    {
        switch (gTestVector_p384[i].numBlocks)
        {
            case 1:
                retVal += knownAnswerTest(gTestVector_p384+i, cid_EC_P384, gpIndicesOneBlock_p384, COUNTOF(gpIndicesOneBlock_p384));
                break;
                
            case 2:
                retVal += knownAnswerTest(gTestVector_p384+i, cid_EC_P384, gpIndicesTwoBlocks_p384, COUNTOF(gpIndicesTwoBlocks_p384));
                break;
                
            case 4:
                retVal += knownAnswerTest(gTestVector_p384+i, cid_EC_P384, gpIndicesFourBlocks_p384, COUNTOF(gpIndicesFourBlocks_p384));
                break;
        }
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(cid_EC_P384, 384);
   
    /* Test the pkcs #1 v1.5 padding API's */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 384;
#endif
    for (i = 0; i < sizeof(gTestVector_p384PKCS)/sizeof(gTestVector_p384PKCS[0]); ++i)
    {
        retVal += knownAnswerTestPKCS(cid_EC_P384, gTestVector_p384PKCS+i);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCasesPKCS(cid_EC_P384, 384);
    
#endif /* __DISABLE_DIGICERT_ECC_P384__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P521__
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 521;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p521); ++i)
    {
        switch (gTestVector_p521[i].numBlocks)
        {
            case 1:
                retVal += knownAnswerTest(gTestVector_p521+i, cid_EC_P521, gpIndicesOneBlock_p521, COUNTOF(gpIndicesOneBlock_p521));
                break;
                
            case 2:
                retVal += knownAnswerTest(gTestVector_p521+i, cid_EC_P521, gpIndicesTwoBlocks_p521, COUNTOF(gpIndicesTwoBlocks_p521));
                break;
                
            case 4:
                retVal += knownAnswerTest(gTestVector_p521+i, cid_EC_P521, gpIndicesFourBlocks_p521, COUNTOF(gpIndicesFourBlocks_p521));
                break;
        }
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(cid_EC_P521, 521);
    
    /* Test the pkcs #1 v1.5 padding API's */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 521;
#endif
    for (i = 0; i < sizeof(gTestVector_p521PKCS)/sizeof(gTestVector_p521PKCS[0]); ++i)
    {
        retVal += knownAnswerTestPKCS(cid_EC_P521, gTestVector_p521PKCS+i);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCasesPKCS(cid_EC_P521, 521);

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
#endif
    retVal += testErrorCasesEnc(cid_EC_P521, &gError_enc_p521[0], -1); /* our error code from the rng callback */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 1;
#endif
    retVal += testErrorCasesEnc(cid_EC_P521, &gError_enc_p521[1], ERR_EC_INFINITE_RESULT);

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
#endif
    retVal += testErrorCasesDec(cid_EC_P521, &gError_dec_p521[0], ERR_EC_INFINITE_RESULT);

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 1;
#endif
    for (i = 1; i < sizeof(gError_dec_p521)/sizeof(gError_dec_p521[0]); ++i)
    {
        retVal += testErrorCasesDec(cid_EC_P521, gError_dec_p521 + i, ERR_ECEG_INVALID_PKCS1_V1P5);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
#endif /* __DISABLE_DIGICERT_ECC_P521__  */

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    DIGICERT_free(&gpMocCtx);

#endif /* defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)*/
    
    return retVal;
}
