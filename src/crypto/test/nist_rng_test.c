/*
 * nist_rng_test.c
 *
 * unit test for nist_rng.c
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
#include "../nist_rng.c"
#include "../nist_rng_ex.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static ubyte mEntropyInput[32] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static ubyte mOutput[72];

/* test vectors in their own files */
#include "ctr_drbg_vectors.inc"


/*-------------------------------------------------------------------------*/

int pr_test_vector_ctr_drbg_aux( MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
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

    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( test->entropyInput, &entropyInput);
    nonceLen = UNITTEST_UTILS_str_to_byteStr( test->nonce, &nonce);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( test->personalizationString,
                                                        &additionalInput);

    /* (1) instantiate */
    if (useDF)
    {
        retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_newDFContext( MOC_SYM(hwAccelCtx)
                                       &pCtx, keyLen, outLen,
                                       entropyInput, entropyInputLen,
                                       nonce, nonceLen,
                                       additionalInput, additionalInputLen));
    }
    else
    {
        retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_newContext( MOC_SYM(hwAccelCtx)
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
    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( test->entropyInputPR1,
                                                        &entropyInput);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( test->additionalInput1,
                                                        &additionalInput);

    /* PR generate is reseed + normal generate */
    retVal += UNITTEST_STATUS( hint,
            NIST_CTRDRBG_reseed(MOC_SYM(hwAccelCtx) pCtx,
                                entropyInput, entropyInputLen,
                                additionalInput, additionalInputLen));
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(hwAccelCtx) pCtx, NULL, 0, block, outLen * 8));

    FREE( entropyInput); entropyInput = 0;
    FREE( additionalInput); additionalInput = 0;

    /* (3) generate one block, print */
    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( test->entropyInputPR2,
                                                        &entropyInput);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( test->additionalInput2,
                                                        &additionalInput);

    /* PR generate is reseed + normal generate */
    retVal += UNITTEST_STATUS( hint,
            NIST_CTRDRBG_reseed(MOC_SYM(hwAccelCtx) pCtx, entropyInput, entropyInputLen,
                                additionalInput, additionalInputLen));
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(hwAccelCtx) pCtx, NULL, 0, block, outLen * 8));

    FREE( entropyInput); entropyInput = 0;
    FREE( additionalInput); additionalInput = 0;

    /* compare */
    resultLen = UNITTEST_UTILS_str_to_byteStr( test->result, &result);

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

    NIST_CTRDRBG_deleteContext(MOC_SYM(hwAccelCtx) &pCtx);

    return retVal;

}


/*-------------------------------------------------------------------------*/

int pr_test_vector_ctr_drbg( MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
                           const NIST_DRBG_TestVectorPR* tests, int numTests,
                           int keyLen, int outLen, int useDF)
{
    int i, retVal = 0;

    for (i = 0; i < numTests; ++i)
    {
        retVal += pr_test_vector_ctr_drbg_aux( MOC_SYM(hwAccelCtx) i + hint*100,
                                                tests + i, keyLen, outLen, useDF);
    }

    return retVal;
}


/*-------------------------------------------------------------------------*/

int nopr_test_vector_ctr_drbg_aux( MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
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

    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( test->entropyInput, &entropyInput);
    nonceLen = UNITTEST_UTILS_str_to_byteStr( test->nonce, &nonce);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( test->personalizationString,
                                                        &additionalInput);

    /* (1) instantiate */
    if (useDF)
    {
        retVal += UNITTEST_STATUS(hint,
                NIST_CTRDRBG_newDFContext( MOC_SYM(hwAccelCtx)
                                        &pCtx, keyLen, outLen,
                                        entropyInput, entropyInputLen,
                                        nonce, nonceLen,
                                        additionalInput, additionalInputLen));
    }
    else
    {
        retVal += UNITTEST_STATUS(hint,
                NIST_CTRDRBG_newContext( MOC_SYM(hwAccelCtx)
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
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( test->additionalInput1,
                                                        &additionalInput);

    /* NoPR generate is normal generate */
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(hwAccelCtx) pCtx,
                                  additionalInput, additionalInputLen,
                                  block, outLen * 8));

    FREE( additionalInput); additionalInput = 0;

    /* (3) reseed */
    entropyInputLen = UNITTEST_UTILS_str_to_byteStr( test->entropyInputReseed,
                                                        &entropyInput);
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( test->additionalInputReseed,
                                                        &additionalInput);

    retVal += UNITTEST_STATUS( hint,
            NIST_CTRDRBG_reseed(MOC_SYM(hwAccelCtx) pCtx,
                                entropyInput, entropyInputLen,
                                additionalInput, additionalInputLen));

    FREE( entropyInput); entropyInput = 0;
    FREE( additionalInput); additionalInput = 0;

    /* (4) generate one block, print */
    additionalInputLen = UNITTEST_UTILS_str_to_byteStr( test->additionalInput2,
                                                        &additionalInput);

    /* NoPR generate is normal generate */
    retVal += UNITTEST_STATUS(hint,
            NIST_CTRDRBG_generate(MOC_SYM(hwAccelCtx) pCtx,
                                  additionalInput, additionalInputLen,
                                  block, outLen * 8));


    /* compare */
    resultLen = UNITTEST_UTILS_str_to_byteStr( test->result, &result);

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

    NIST_CTRDRBG_deleteContext(MOC_SYM(hwAccelCtx) &pCtx);

    return retVal;

}


/*-------------------------------------------------------------------------*/

int nopr_test_vector_ctr_drbg( MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
                           const NIST_DRBG_TestVectorNoPR* tests, int numTests,
                           int keyLen, int outLen, int useDF)
{
    int i, retVal = 0;

    for (i = 0; i < numTests; ++i)
    {
        retVal += nopr_test_vector_ctr_drbg_aux( MOC_SYM(hwAccelCtx) i + hint*100,
                                                tests + i, keyLen, outLen, useDF);
    }

    return retVal;
}


/*-------------------------------------------------------------------------*/
/* Split the nist_rng_test_vector tests into two function since the vxWorks remote tests
 * seemed to timeout for some yet to be determined reason		// cdsxxx
 */
int nist_rng_test_vectors1()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

    retVal += UNITTEST_STATUS(0,
            HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if ( 0 == retVal)
    {
#if 0
        /* TDES does not work -- unsure why, probably because of the
        key handling -> 56-168bits vs. 64-192 bits ? */
        /* TDES no DF */
        retVal += nopr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            2, kCTR_DRBG_TDES_NoPR,
                                            COUNTOF(kCTR_DRBG_TDES_NoPR),
                                            21, THREE_DES_BLOCK_SIZE, 0);
        retVal += pr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            3, kCTR_DRBG_TDES_PR,
                                            COUNTOF(kCTR_DRBG_TDES_PR),
                                            21, THREE_DES_BLOCK_SIZE, 0);
#endif


        /* AES128 DF */
        retVal += nopr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            4, kCTR_DRBG_AES128_DF_NoPR,
                                            COUNTOF(kCTR_DRBG_AES128_DF_NoPR),
                                            16, AES_BLOCK_SIZE, 1);

        retVal += pr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            5, kCTR_DRBG_AES128_DF_PR,
                                            COUNTOF(kCTR_DRBG_AES128_DF_PR),
                                            16, AES_BLOCK_SIZE, 1);
        /* AES192 DF */

        retVal += nopr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            6, kCTR_DRBG_AES192_DF_NoPR,
                                            COUNTOF(kCTR_DRBG_AES192_DF_NoPR),
                                            24, AES_BLOCK_SIZE, 1);

        retVal += pr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            7, kCTR_DRBG_AES192_DF_PR,
                                            COUNTOF(kCTR_DRBG_AES192_DF_PR),
                                            24, AES_BLOCK_SIZE, 1);
        /* AES256 DF */

        retVal += nopr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            8, kCTR_DRBG_AES256_DF_NoPR,
                                            COUNTOF(kCTR_DRBG_AES256_DF_NoPR),
                                            32, AES_BLOCK_SIZE, 1);

        retVal += pr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            9, kCTR_DRBG_AES256_DF_PR,
                                            COUNTOF(kCTR_DRBG_AES256_DF_PR),
                                            32, AES_BLOCK_SIZE, 1);

        /* AES128 no DF */

        retVal += nopr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            10, kCTR_DRBG_AES128_NoPR,
                                            COUNTOF(kCTR_DRBG_AES128_NoPR),
                                            16, AES_BLOCK_SIZE, 0);

        retVal += pr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            11, kCTR_DRBG_AES128_PR,
                                            COUNTOF(kCTR_DRBG_AES128_PR),
                                            16, AES_BLOCK_SIZE, 0);
        /* AES192 no DF */

        retVal += nopr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            12, kCTR_DRBG_AES192_NoPR,
                                            COUNTOF(kCTR_DRBG_AES192_NoPR),
                                            24, AES_BLOCK_SIZE, 0);

        retVal += pr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            13, kCTR_DRBG_AES192_PR,
                                            COUNTOF(kCTR_DRBG_AES192_PR),
                                            24, AES_BLOCK_SIZE, 0);
        /* AES256 no DF */

        retVal += nopr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            14, kCTR_DRBG_AES256_NoPR,
                                            COUNTOF(kCTR_DRBG_AES256_NoPR),
                                            32, AES_BLOCK_SIZE, 0);

        retVal += pr_test_vector_ctr_drbg(MOC_SYM(hwAccelCtx)
                                            15, kCTR_DRBG_AES256_PR,
                                            COUNTOF(kCTR_DRBG_AES256_PR),
                                            32, AES_BLOCK_SIZE, 0);

    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    return retVal;
}

int nist_rng_test_vectors2()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

    retVal += UNITTEST_STATUS(0,
            HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if ( 0 == retVal)
    {

    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    return retVal;
}


int nist_rng_test_vectors3()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

    retVal += UNITTEST_STATUS(0,
            HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if ( 0 == retVal)
    {
        /* P384 SHA512 */
#if 0
        retVal += nopr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            32, kEC_DRBG_P384_SHA512_NoPR,
                                            COUNTOF(kEC_DRBG_P384_SHA512_NoPR),
                                            EC_P384, ht_sha512);

        retVal += pr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            33, kEC_DRBG_P384_SHA512_PR,
                                            COUNTOF(kEC_DRBG_P384_SHA512_PR),
                                            EC_P384, ht_sha512);
        /* P521 SHA256 */

        retVal += nopr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            34, kEC_DRBG_P521_SHA256_NoPR,
                                            COUNTOF(kEC_DRBG_P521_SHA256_NoPR),
                                            EC_P521, ht_sha256);


        retVal += pr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            35, kEC_DRBG_P521_SHA256_PR,
                                            COUNTOF(kEC_DRBG_P521_SHA256_PR),
                                            EC_P521, ht_sha256);
       /* P521 SHA384 */

        retVal += nopr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            36, kEC_DRBG_P521_SHA384_NoPR,
                                            COUNTOF(kEC_DRBG_P521_SHA384_NoPR),
                                            EC_P521, ht_sha384);

        retVal += pr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            37, kEC_DRBG_P521_SHA384_PR,
                                            COUNTOF(kEC_DRBG_P521_SHA384_PR),
                                            EC_P521, ht_sha384);
        /* P521 SHA512 */

        retVal += nopr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            38, kEC_DRBG_P521_SHA512_NoPR,
                                            COUNTOF(kEC_DRBG_P521_SHA512_NoPR),
                                            EC_P521, ht_sha512);

        retVal += pr_test_vector_ec_drbg(MOC_SYM(hwAccelCtx)
                                            39, kEC_DRBG_P521_SHA512_PR,
                                            COUNTOF(kEC_DRBG_P521_SHA512_PR),
                                            EC_P521, ht_sha512);
#endif
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    return retVal;
}

/*-------------------------------------------------------------------------*/

int nist_rng_test_secret()
{
    int retVal = 0;
    randomContext *pCtx = 0;
    sbyte4 compare;
    ubyte pSeed[32] = {0x01,0x02,0x03,0x04};

    ubyte pSecret[128] = {0};

    ubyte pNextGen[96] = {0};
    ubyte pNextGen2[96] = {0};

    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_newContext(&pCtx, pSeed, 16, 16, NULL, 0));
    if (retVal)
        goto exit;

    /* call generate a couple times for some arbitrary number of bits */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(pCtx, NULL, 0, pNextGen, 32)); /* in bits */
    if (retVal)
        goto exit;

    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(pCtx, NULL, 0, pNextGen, 199)); /* in bits */
    if (retVal)
        goto exit;

    /* call generate secret which will also save the state */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generateSecret(pCtx, NULL, 0, pSecret, sizeof(pSecret)));
    if (retVal)
        goto exit;

    /* call generate to get the bits from the following state */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(pCtx, NULL, 0, pNextGen, sizeof(pNextGen) * 8)); /* in bits */
    if (retVal)
        goto exit;

    /* delete the context and reset */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_deleteContext(&pCtx));
    if (retVal)
        goto exit;

    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_newContext(&pCtx, pSeed, 16, 16, NULL, 0));
    if (retVal)
        goto exit;

    /* set the state to the saved one in pSecret */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_setStateFromSecret(pCtx, NULL, 0, pSecret, sizeof(pSecret)));
    if (retVal)
        goto exit;

    /* generate bits again from the following state */
    retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_generate(pCtx, NULL, 0, pNextGen2, sizeof(pNextGen2) * 8)); /* in bits */
    if (retVal)
        goto exit;

    /* check if the bits from that state match what they should be */
    DIGI_MEMCMP(pNextGen, pNextGen2, sizeof(pNextGen), &compare);

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtx )
        retVal += UNITTEST_STATUS(__MOC_LINE__, NIST_CTRDRBG_deleteContext(&pCtx));

    return retVal;
}
