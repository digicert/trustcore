/*
*  crypto_interface_nist_ctrdrbg_test.c
*
*   unit test for nist_rng.c
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
#include "../../crypto/aes.h"
#include "../../common/random.h"
#include "../../crypto/nist_rng.h"
#include "../../crypto/nist_rng_ex.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#if (!defined(__DISABLE_AES_CIPHERS__))

static MocCtx gpMocCtx = NULL;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static ubyte gAddInput[32] =
{ 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

#include "../../crypto_interface/test/ctr_drbg_vectors_inc.h"

/*-------------------------------------------------------------------------*/

static int pr_test_vector_ctr_drbg_aux( int hint,
                           const NIST_DRBG_TestVectorPR* test, 
                           int keyLen, int outLen, int useDF)
{
    int retVal = 0;
    randomContext* pCtx = 0;
    ubyte* entropyInput = 0;
    ubyte4 entropyInputLen;
    ubyte* nonce = 0;
    ubyte4 nonceLen;
    ubyte* additionalInput = 0;
    ubyte4 additionalInputLen;
    ubyte* result = 0;
    ubyte4 resultLen;
    ubyte* block = 0;
    sbyte4 rescmp;

    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *)test->entropyInput, &entropyInput);
    nonceLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->nonce, &nonce);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->personalizationString,
                                                        &additionalInput);

    /* (1) instantiate */
    if (useDF)
    {
        retVal += UNITTEST_STATUS(hint, 
            NIST_CTRDRBG_newDFContext( MOC_SYM(gpHwAccelCtx)
                                       &pCtx, keyLen, outLen,
                                       entropyInput, entropyInputLen,  
                                       nonce, nonceLen,
                                       additionalInput, additionalInputLen));
    }
    else
    {
        retVal += UNITTEST_STATUS(hint, 
            NIST_CTRDRBG_newContext( MOC_SYM(gpHwAccelCtx)
                                       &pCtx, 
                                       entropyInput, keyLen, outLen,                                       
                                       additionalInput, additionalInputLen));

    }

    if (retVal) goto exit;
    FREE( entropyInput); entropyInput = 0;
    FREE( nonce); nonce = 0;
    FREE( additionalInput); additionalInput = 0;

    block = MALLOC( outLen);
    retVal += UNITTEST_TRUE( hint, block != NULL);
    if (retVal) goto exit;

    /* (2) generate one block, do not print */
    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->entropyInputPR1,
                                                        &entropyInput);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->additionalInput1,
                                                        &additionalInput);
   
    /* PR generate is reseed + normal generate */
    retVal += UNITTEST_STATUS( hint, 
            NIST_CTRDRBG_reseed(MOC_SYM(gpHwAccelCtx) pCtx,
                                entropyInput, entropyInputLen,
                                additionalInput, additionalInputLen));
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx, NULL, 0, block, outLen * 8));

    FREE( entropyInput); entropyInput = 0;
    FREE( additionalInput); additionalInput = 0;

    /* (3) generate one block, print */
    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->entropyInputPR2,
                                                        &entropyInput);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->additionalInput2,
                                                        &additionalInput);
   
    /* PR generate is reseed + normal generate */
    retVal += UNITTEST_STATUS( hint, 
            NIST_CTRDRBG_reseed(MOC_SYM(gpHwAccelCtx) pCtx, entropyInput, entropyInputLen,
                                additionalInput, additionalInputLen));
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx, NULL, 0, block, outLen * 8));

    FREE( entropyInput); entropyInput = 0;
    FREE( additionalInput); additionalInput = 0;

    /* compare */
    resultLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->result, &result);

    DIGI_MEMCMP( result, block, outLen, &rescmp);
    retVal += UNITTEST_TRUE(hint, 0 == rescmp);

exit:

    if ( entropyInput)
    {
        FREE(entropyInput);
    }
    if ( nonce)
    {
        FREE(nonce);
    }
    if ( additionalInput)
    {
        FREE(additionalInput);
    }
    if (block)
    {
        FREE(block);
    }
    if (result)
    {
        FREE(result);
    }

    NIST_CTRDRBG_deleteContext(MOC_SYM(gpHwAccelCtx) &pCtx);

    return retVal;
}


/*-------------------------------------------------------------------------*/

static int pr_test_vector_ctr_drbg( int hint,
                           const NIST_DRBG_TestVectorPR* tests, int numTests,
                           int keyLen, int outLen, int useDF)
{
    int i, retVal = 0;

    for (i = 0; i < numTests; ++i)
    {
        retVal += pr_test_vector_ctr_drbg_aux( i + hint*100, 
                                                tests + i, keyLen, outLen, useDF);
    }

    return retVal;
}


/*-------------------------------------------------------------------------*/

static int nopr_test_vector_ctr_drbg_aux( int hint,
                           const NIST_DRBG_TestVectorNoPR* test, 
                           int keyLen, int outLen, int useDF)
{
    int retVal = 0;
    randomContext* pCtx = 0;
    ubyte* entropyInput = 0;
    ubyte4 entropyInputLen;
    ubyte* nonce = 0;
    ubyte4 nonceLen;
    ubyte* additionalInput = 0;
    ubyte4 additionalInputLen;
    ubyte* result = 0;
    ubyte4 resultLen;
    ubyte* block = 0;
    sbyte4 rescmp;

    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->entropyInput, &entropyInput);
    nonceLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->nonce, &nonce);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->personalizationString,
                                                        &additionalInput);

    /* (1) instantiate */
    if (useDF)
    {
        retVal += UNITTEST_STATUS(hint, 
                NIST_CTRDRBG_newDFContext( MOC_SYM(gpHwAccelCtx)
                                        &pCtx, keyLen, outLen,
                                        entropyInput, entropyInputLen,
                                        nonce, nonceLen,
                                        additionalInput, additionalInputLen));
    }
    else
    {
        retVal += UNITTEST_STATUS(hint, 
                NIST_CTRDRBG_newContext( MOC_SYM(gpHwAccelCtx)
                                        &pCtx, entropyInput,
                                        keyLen, outLen, 
                                        additionalInput, additionalInputLen));
    }

    if (retVal) goto exit;
    FREE( entropyInput); entropyInput = 0;
    FREE( nonce); nonce = 0;
    FREE( additionalInput); additionalInput = 0;

    block = MALLOC( outLen);
    retVal += UNITTEST_TRUE( hint, block != NULL);
    if (retVal) goto exit;

    /* (2) generate one block, do not print */
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->additionalInput1,
                                                        &additionalInput);
   
    /* NoPR generate is normal generate */
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx,
                                  additionalInput, additionalInputLen,
                                  block, outLen * 8));

    FREE( additionalInput); additionalInput = 0;

    /* (3) reseed */
    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->entropyInputReseed,
                                                        &entropyInput);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->additionalInputReseed,
                                                        &additionalInput);

    retVal += UNITTEST_STATUS( hint, 
            NIST_CTRDRBG_reseed(MOC_SYM(gpHwAccelCtx) pCtx,
                                entropyInput, entropyInputLen,
                                additionalInput, additionalInputLen));

    FREE( entropyInput); entropyInput = 0;
    FREE( additionalInput); additionalInput = 0;

    /* (4) generate one block, print */
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->additionalInput2,
                                                        &additionalInput);
   
    /* NoPR generate is normal generate */
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx,
                                  additionalInput, additionalInputLen,
                                  block, outLen * 8));


    /* compare */
    resultLen = UNITTEST_UTILS_str_to_byteStr( (const sbyte *) test->result, &result);

    DIGI_MEMCMP( result, block, outLen, &rescmp);
    retVal += UNITTEST_TRUE(hint, 0 == rescmp);
    
exit:
    
    if ( entropyInput)
    {
        FREE(entropyInput);
    }
    if ( nonce)
    {
        FREE(nonce);
    }
    if ( additionalInput)
    {
        FREE(additionalInput);
    }
    if (block)
    {
        FREE(block);
    }
    if (result)
    {
        FREE(result);
    }

    NIST_CTRDRBG_deleteContext(MOC_SYM(gpHwAccelCtx) &pCtx);

    return retVal;
}


/*-------------------------------------------------------------------------*/

static int nopr_test_vector_ctr_drbg( int hint,
                           const NIST_DRBG_TestVectorNoPR* tests, int numTests,
                           int keyLen, int outLen, int useDF)
{
    int i, retVal = 0;

    for (i = 0; i < numTests; ++i)
    {
        retVal += nopr_test_vector_ctr_drbg_aux( i + hint*100, 
                                                tests + i, keyLen, outLen, useDF);
    }

    return retVal;
}


/*-------------------------------------------------------------------------*/
/* Split the nist_rng_test_vector tests into two function since the vxWorks remote tests
 * seemed to timeout for some yet to be determined reason		// cdsxxx
 */
static int nist_rng_test_vectors1()
{
    int retVal = 0;

    /* AES256 DF, the only ones supported by mbed */
    
    retVal += nopr_test_vector_ctr_drbg(8, kCTR_DRBG_AES256_DF_NoPR,
                                        COUNTOF(kCTR_DRBG_AES256_DF_NoPR),
                                        32, AES_BLOCK_SIZE, 1);
    
    retVal += pr_test_vector_ctr_drbg(9, kCTR_DRBG_AES256_DF_PR,
                                      COUNTOF(kCTR_DRBG_AES256_DF_PR),
                                      32, AES_BLOCK_SIZE, 1);
    
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CTR_DRBG_AES_MBED__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG__)
    
    /* AES128 DF */
    retVal += nopr_test_vector_ctr_drbg(4, kCTR_DRBG_AES128_DF_NoPR,
                                        COUNTOF(kCTR_DRBG_AES128_DF_NoPR),
                                        16, AES_BLOCK_SIZE, 1);
    
    retVal += pr_test_vector_ctr_drbg(5, kCTR_DRBG_AES128_DF_PR,
                                      COUNTOF(kCTR_DRBG_AES128_DF_PR),
                                      16, AES_BLOCK_SIZE, 1);
    /* AES192 DF */
    
    retVal += nopr_test_vector_ctr_drbg(6, kCTR_DRBG_AES192_DF_NoPR,
                                        COUNTOF(kCTR_DRBG_AES192_DF_NoPR),
                                        24, AES_BLOCK_SIZE, 1);
    
    retVal += pr_test_vector_ctr_drbg(7, kCTR_DRBG_AES192_DF_PR,
                                      COUNTOF(kCTR_DRBG_AES192_DF_PR),
                                      24, AES_BLOCK_SIZE, 1);
    
    /* AES128 no DF */
    
    retVal += nopr_test_vector_ctr_drbg(10, kCTR_DRBG_AES128_NoPR,
                                        COUNTOF(kCTR_DRBG_AES128_NoPR),
                                        16, AES_BLOCK_SIZE, 0);
    
    retVal += pr_test_vector_ctr_drbg(11, kCTR_DRBG_AES128_PR,
                                      COUNTOF(kCTR_DRBG_AES128_PR),
                                      16, AES_BLOCK_SIZE, 0);
    /* AES192 no DF */
    
    retVal += nopr_test_vector_ctr_drbg(12, kCTR_DRBG_AES192_NoPR,
                                        COUNTOF(kCTR_DRBG_AES192_NoPR),
                                        24, AES_BLOCK_SIZE, 0);
    
    retVal += pr_test_vector_ctr_drbg(13, kCTR_DRBG_AES192_PR,
                                      COUNTOF(kCTR_DRBG_AES192_PR),
                                      24, AES_BLOCK_SIZE, 0);
    /* AES256 no DF */
    
    retVal += nopr_test_vector_ctr_drbg(14, kCTR_DRBG_AES256_NoPR,
                                        COUNTOF(kCTR_DRBG_AES256_NoPR),
                                        32, AES_BLOCK_SIZE, 0);
    
    retVal += pr_test_vector_ctr_drbg(15, kCTR_DRBG_AES256_PR,
                                      COUNTOF(kCTR_DRBG_AES256_PR),
                                      32, AES_BLOCK_SIZE, 0);
    
#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CTR_DRBG_AES_MBED__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG__) */
    
    return retVal;
}

/*-------------------------------------------------------------------------*/

static int nist_rng_test_secret(ubyte withDf, ubyte *pAddInput, ubyte4 addInputLen, ubyte4 keyLen)
{
    int retVal = 0;
    randomContext *pCtx = 0;
    sbyte4 compare;
    ubyte pSeed[48] = {0x01,0x02,0x03,0x04}; /* big enough for 32 byte keys */
    
    ubyte pSecret[128] = {0};
    
    ubyte pNextGen[96] = {0};
    ubyte pNextGen2[96] = {0};
    
    if (withDf)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_newDFContext(MOC_SYM(gpHwAccelCtx) &pCtx, keyLen, 16, pSeed, keyLen + 16, NULL, 0, NULL, 0));
        if (retVal)
            goto exit;
    }
    else
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_newContext(MOC_SYM(gpHwAccelCtx) &pCtx, pSeed, keyLen, 16, NULL, 0));
        if (retVal)
            goto exit;
    }
    
    /* call generate a couple times for some arbitrary number of bits */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx, NULL, 0, pNextGen, 32)); /* in bits */
    if (retVal)
        goto exit;
    
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx, NULL, 0, pNextGen, 199)); /* in bits */
    if (retVal)
        goto exit;
    
    /* call generate secret which will also save the state */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generateSecret(MOC_SYM(gpHwAccelCtx) pCtx, pAddInput, addInputLen, pSecret, sizeof(pSecret)));
    if (retVal)
        goto exit;
    
    /* call generate to get the bits from the following state */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx, NULL, 0, pNextGen, sizeof(pNextGen) * 8)); /* in bits */
    if (retVal)
        goto exit;
    
    /* delete the context and reset */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_deleteContext(MOC_SYM(gpHwAccelCtx) &pCtx));
    if (retVal)
        goto exit;
    
    if (withDf)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_newDFContext(MOC_SYM(gpHwAccelCtx) &pCtx, keyLen, 16, pSeed, keyLen + 16, NULL, 0, NULL, 0));
        if (retVal)
            goto exit;
    }
    else
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_newContext(MOC_SYM(gpHwAccelCtx) &pCtx, pSeed, keyLen, 16, NULL, 0));
        if (retVal)
            goto exit;
    }
    
    /* set the state to the saved one in pSecret */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_setStateFromSecret(MOC_SYM(gpHwAccelCtx) pCtx, pAddInput, addInputLen, pSecret, sizeof(pSecret)));
    if (retVal)
        goto exit;
    
    /* generate bits again from the following state */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(MOC_SYM(gpHwAccelCtx) pCtx, NULL, 0, pNextGen2, sizeof(pNextGen2) * 8)); /* in bits */
    if (retVal)
        goto exit;
    
    /* check if the bits from that state match what they should be */
    DIGI_MEMCMP(pNextGen, pNextGen2, sizeof(pNextGen), &compare);
    
    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pCtx )
        retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_deleteContext(MOC_SYM(gpHwAccelCtx) &pCtx));
    
    return retVal;
}

#endif /* (!defined(__DISABLE_AES_CIPHERS__)) */

int crypto_interface_nist_ctrdrbg_test()
{
    int retVal = 0;

#if (!defined(__DISABLE_AES_CIPHERS__))
    
    MSTATUS status;
    InitMocanaSetupInfo setupInfo = {0};
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
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

    retVal += nist_rng_test_vectors1();

    /* mbed supports only 32 byte keys and with-df mode */
    retVal += nist_rng_test_secret(1, NULL, 0, 32);
    retVal += nist_rng_test_secret(1, gAddInput, sizeof(gAddInput), 32);
    
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CTR_DRBG_AES_MBED__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG__)

    retVal += nist_rng_test_secret(0, NULL, 0, 32);
    retVal += nist_rng_test_secret(0, NULL, 0, 16);
    retVal += nist_rng_test_secret(0, NULL, 0, 24);
    
    retVal += nist_rng_test_secret(1, NULL, 0, 16);
    retVal += nist_rng_test_secret(1, NULL, 0, 24);
   
    retVal += nist_rng_test_secret(0, gAddInput, sizeof(gAddInput), 16);
    retVal += nist_rng_test_secret(0, gAddInput, sizeof(gAddInput), 24);
    retVal += nist_rng_test_secret(0, gAddInput, sizeof(gAddInput), 32);
    
    retVal += nist_rng_test_secret(1, gAddInput, sizeof(gAddInput), 16);
    retVal += nist_rng_test_secret(1, gAddInput, sizeof(gAddInput), 24);

#endif
    
exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    
#endif /* (!defined(__DISABLE_AES_CIPHERS__)) */
    
    return retVal;
}
