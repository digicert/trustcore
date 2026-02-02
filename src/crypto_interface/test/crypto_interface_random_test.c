/*
 * crypto_interface_random_test.c
 *
 * test cases for CTR-DRBG APIs
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
#include "../../../unit_tests/unittest.h"
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/sha1.h"
#include "../../crypto/aesalgo.h"
#include "../../crypto/aes.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/nist_rng.h"
#include "../../crypto/nist_rng_types.h"
#include "../../common/random.h"
#include "../../common/rng_seed.h"
#include "../../crypto_interface/crypto_interface_random.h"
#include "../../../unit_tests/unittest_utils.h"

/*------------------------------------------------------------------*/

static MocCtx gpMocCtx = NULL;
ubyte *g_pEntropyBuf;
ubyte4 g_entropyLen;
ubyte *g_pPersoStr;
ubyte4 g_persoStrLen;

/*------------------------------------------------------------------*/

#include "ctr_drbg_vectors_inc.h"

/*------------------------------------------------------------------*/

MSTATUS customEntropyFunc(void *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
  ubyte4 i;

  for (i = 0; i < bufferLen; i++)
  {
    pBuffer[i] = g_pEntropyBuf[i];
  }

  return OK;
}

ubyte* customGetPersoStrFunc(ubyte4 *pLen)
{
  if (NULL == pLen)
    return NULL;

  *pLen = g_persoStrLen;
  return g_pPersoStr;
}

/*------------------------------------------------------------------*/

static MSTATUS testCtrDrbgAddEntropy()
{
  MSTATUS status;
  randomContext *pRandCtx = NULL;
  RandomCtxWrapper *pWrapper = NULL;
  ubyte4 entropyLen = MOC_DEFAULT_NUM_ENTROPY_BYTES;
  ubyte4 outLen = AES_BLOCK_SIZE;
  ubyte pAddEntropy[MOC_DEFAULT_NUM_ENTROPY_BYTES];
  ubyte pOut[AES_BLOCK_SIZE];
  ubyte4 i, j, bitCounter;
  ubyte entByte;

  /* Use the global random to generate bytes to serve as additional
   * entropy into the pool. */
  status = RANDOM_numberGenerator(g_pRandomContext, pAddEntropy, entropyLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Create a new random context, this will perform the initial seeding */
  status = RANDOM_acquireContext(&pRandCtx);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Validate that the reseedBit counter is zero */
  pWrapper = (RandomCtxWrapper *)pRandCtx;

  if (0 != pWrapper->reseedBitCounter)
  {
    status = ERR_RAND_INVALID_CONTEXT;
    UNITTEST_STATUS(__MOC_LINE__, status);
    goto exit;
  }

  /* Generate a block of data to ensure everything is working properly, if FIPS make sure to seed */
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
  status = NIST_CTRDRBG_reseed(pRandCtx, pAddEntropy, MOC_DEFAULT_NUM_ENTROPY_BYTES, NULL, 0);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

#endif
  status = RANDOM_numberGenerator(pRandCtx, pOut, outLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Add half of the entropy into the depot */
  bitCounter = 0;
  for (i = 0; i < entropyLen/2; i++)
  {
    entByte = pAddEntropy[i];
    for (j = 8; j > 0; j--)
    {
      status = RANDOM_addEntropyBit(pRandCtx, entByte);
      UNITTEST_STATUS(__MOC_LINE__, status);
      if (OK != status)
        goto exit;

      entByte >>= 1;
      bitCounter++;
    }
  }

  /* Make sure the bit counter matches */
  if (bitCounter != pWrapper->reseedBitCounter)
  {
    status = ERR_CMP;
    UNITTEST_STATUS(__MOC_LINE__, status);
    goto exit;
  }

  /* Add the rest, this should trigger a reseed */
  for (i = entropyLen/2; i < entropyLen; i++)
  {
    entByte = pAddEntropy[i];
    for (j = 8; j > 0; j--)
    {
      status = RANDOM_addEntropyBit(pRandCtx, entByte);
      UNITTEST_STATUS(__MOC_LINE__, status);
      if (OK != status)
        goto exit;

      entByte >>= 1;
    }
  }

  /* Ensure the reseedBitCounter is zero */
  if (0 != pWrapper->reseedBitCounter)
  {
    status = ERR_RAND_INVALID_CONTEXT;
    UNITTEST_STATUS(__MOC_LINE__, status);
    goto exit;
  }

  /* Validate we can still generate bytes after reseed */
  status = RANDOM_numberGenerator(pRandCtx, pOut, outLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

exit:

  if (NULL != pRandCtx)
  {
    RANDOM_releaseContext(&pRandCtx);
  }

  return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__

static MSTATUS testMbedCtrDrbgVector (
  const NIST_DRBG_TestVectorNoPR *pTest
  )
{
  MSTATUS status;
  ubyte pBlock[AES_BLOCK_SIZE] = {0};
  randomContext *pRandCtx = NULL;
  ubyte *pEntropy = NULL;
  ubyte4 entropyLen = 0;
  ubyte *pNonce = NULL;
  ubyte4 nonceLen = 0;
  ubyte *pAdd = NULL;
  ubyte4 addLen = 0;
  ubyte *pConcat = NULL;
  ubyte4 concatLen = 0;
  ubyte *pResult = NULL;
  ubyte4 resultLen = 0;
  ubyte4 outLen = AES_BLOCK_SIZE;
  sbyte4 cmpRes = 0;
  ubyte4 i;

  entropyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->entropyInput, &pEntropy);
  nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->nonce, &pNonce);
  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->personalizationString, &pAdd);

  /* The underlying mbed API does not have parameters for specifying the nonce
   * separately. Instead we take advantage of the knowledge that any underlying
   * implementation will form (entropy || nonce || persoStr) per NIST SP 800-90A
   * Rev1 10.2.1.3.2.  We then specify the personalizatioon string as the
   * concatenation of the nonce and the personalization string */
  concatLen = nonceLen + addLen;
  status = DIGI_MALLOC((void **)&pConcat, concatLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_MEMCPY(pConcat, pNonce, nonceLen);
  DIGI_MEMCPY(pConcat + nonceLen, pAdd, addLen);

  /* Register the custom entropy function */
  status = CRYPTO_INTERFACE_registerEntropyFunc(customEntropyFunc, entropyLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Register the custom callback for retrieving the personalization string */
  status = CRYPTO_INTERFACE_regsterGetPersoStrCallback(customGetPersoStrFunc);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Set the global pointers for when the callbacks are invoked */
  g_pEntropyBuf = pEntropy;
  g_entropyLen = entropyLen;
  g_pPersoStr = pConcat;
  g_persoStrLen = concatLen;

  /* Acquire the context, this will invoke the entropy function which will copy
   * over the fixed data. It will also invoke our callback to get the
   * personalization string, which in our case is actually the concatenation
   * of (nonce || persoStr) */
  status = RANDOM_acquireContext(&pRandCtx);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Free the buffers we previously allocated. Some of these may be NULL
   * so we perform no status checks */
  DIGI_FREE((void **)&pEntropy);
  DIGI_FREE((void **)&pNonce);
  DIGI_FREE((void **)&pAdd);
  DIGI_FREE((void **)&pConcat);

  /* Get the additional input for the next generate call */
  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->additionalInput1, &pAdd);

  /* Generate a single block of data with additional input */
  status = RANDOM_numberGeneratorAdd (
    pRandCtx, pBlock, outLen, pAdd, addLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_FREE((void **)&pEntropy);
  DIGI_FREE((void **)&pAdd);

  /* Set up the entropy buffer and additional input for the reseed */
  entropyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->entropyInputReseed, &pEntropy);
  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->additionalInputReseed, &pAdd);
  g_pEntropyBuf = pEntropy;
  g_entropyLen = entropyLen;

  /* Perform the reseed. Note we do not pass the entropy in directly, it will
   * get picked up through the callback we registered earlier */
  status = RANDOM_reseedContext (
    pRandCtx, NULL, 0, pAdd, addLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_FREE((void **)&pEntropy);
  DIGI_FREE((void **)&pAdd);

  /* Get the additional input for the final generate */
  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->additionalInput2, &pAdd);

  /* Generate the final result */
  status = RANDOM_numberGeneratorAdd (
    pRandCtx, pBlock, outLen, pAdd, addLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Get the result and compare */
  resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->result, &pResult);

  status = DIGI_MEMCMP(pResult, pBlock, AES_BLOCK_SIZE, &cmpRes);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  if (0 != cmpRes)
  {
    status = ERR_CMP;
    UNITTEST_STATUS(__MOC_LINE__, status);
    goto exit;
  }

exit:

  if (NULL != pEntropy)
  {
    DIGI_FREE((void **)&pEntropy);
  }
  if (NULL != pNonce)
  {
    DIGI_FREE((void **)&pNonce);
  }
  if (NULL != pAdd)
  {
    DIGI_FREE((void **)&pAdd);
  }
  if (NULL != pResult)
  {
    DIGI_FREE((void **)&pResult);
  }
  if (NULL != pRandCtx)
  {
    RANDOM_releaseContext(&pRandCtx);
  }

  CRYPTO_INTERFACE_unregisterFuncs();

  return status;
}

/*------------------------------------------------------------------*/

static MSTATUS testMbedCtrDrbgVectors (
  const NIST_DRBG_TestVectorNoPR *pTests,
  ubyte4 numTests
  )
{
  int i, retVal = 0;

  for (i = 0; i < numTests; i++)
  {
    retVal += testMbedCtrDrbgVector(pTests + i);
  }

  return retVal;
}

/*------------------------------------------------------------------*/

static MSTATUS testMbedCtrDrbg (
  const NIST_DRBG_TestVectorNoPR *pTests,
  ubyte4 numTests
  )
{
  int retVal = 0;

  retVal += testCtrDrbgAddEntropy();
  retVal += testMbedCtrDrbgVectors(pTests, numTests);

  return retVal;
}

/*------------------------------------------------------------------*/
/*------------------------------------------------------------------*/

#else /* ifdef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__ */

/*------------------------------------------------------------------*/
/*------------------------------------------------------------------*/

static MSTATUS testMocanaCtrDrbgVector (
  const NIST_DRBG_TestVectorNoPR *pTest
  )
{
  MSTATUS status;
  ubyte pBlock[AES_BLOCK_SIZE] = {0};
  randomContext *pRandCtx = NULL;
  ubyte *pEntropy = NULL;
  ubyte4 entropyLen = 0;
  ubyte *pNonce = NULL;
  ubyte4 nonceLen = 0;
  ubyte *pResult = NULL;
  ubyte *pAdd = NULL;
  ubyte4 addLen = 0;
  ubyte4 resultLen = 0;
  ubyte4 outLen = AES_BLOCK_SIZE;
  sbyte4 cmpRes = 0;
  hwAccelDescr hwAccelCtx = 0;
  
  entropyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->entropyInput, &pEntropy);
  nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->nonce, &pNonce);
  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->personalizationString, &pAdd);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
    goto exit;
    
  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
    goto exit;
#endif

  status = NIST_CTRDRBG_newDFContext ( MOC_SYM(hwAccelCtx)
    &pRandCtx, 32, 16, pEntropy, entropyLen, pNonce, nonceLen, pAdd, addLen);
  if (OK != status)
    goto exit;

  status = DIGI_FREE((void **)&pAdd);
  if (OK != status)
    goto exit;

  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->additionalInput1, &pAdd);

  status = RANDOM_numberGeneratorAdd (
    pRandCtx, pBlock, outLen, pAdd, addLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_FREE((void **)&pEntropy);
  DIGI_FREE((void **)&pAdd);

  entropyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *)pTest->entropyInputReseed, &pEntropy);
  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->additionalInputReseed, &pAdd);

  status = RANDOM_reseedContext (
    pRandCtx, pEntropy, entropyLen, pAdd, addLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_FREE((void **)&pEntropy);
  DIGI_FREE((void **)&pAdd);

  addLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->additionalInput2, &pAdd);

  status = RANDOM_numberGeneratorAdd (
    pRandCtx, pBlock, outLen, pAdd, addLen);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTest->result, &pResult);

  status = DIGI_MEMCMP(pResult, pBlock, AES_BLOCK_SIZE, &cmpRes);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  if (0 != cmpRes)
  {
    status = ERR_CMP;
    UNITTEST_STATUS(__MOC_LINE__, status);
    goto exit;
  }

exit:

  if (NULL != pEntropy)
  {
    DIGI_FREE((void **)&pEntropy);
  }
  if (NULL != pNonce)
  {
    DIGI_FREE((void **)&pNonce);
  }
  if (NULL != pAdd)
  {
    DIGI_FREE((void **)&pAdd);
  }
  if (NULL != pResult)
  {
    DIGI_FREE((void **)&pResult);
  }
  if (NULL != pRandCtx)
  {
    NIST_CTRDRBG_deleteContext(MOC_SYM(hwAccelCtx) &pRandCtx);
  }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

  return status;

}

/*------------------------------------------------------------------*/

static MSTATUS testMocanaCtrDrbgVectors (
  const NIST_DRBG_TestVectorNoPR *pTests,
  ubyte4 numTests
  )
{
  int i, retVal = 0;

  for (i = 0; i < numTests; i++)
  {
    retVal += testMocanaCtrDrbgVector(pTests + i);
  }

  return retVal;
}

/*------------------------------------------------------------------*/

static MSTATUS testMocanaCtrDrbg (
  const NIST_DRBG_TestVectorNoPR *pTests,
  ubyte4 numTests
  )
{
  int retVal = 0;

  retVal += testCtrDrbgAddEntropy();
  retVal += testMocanaCtrDrbgVectors(pTests, numTests);

  return retVal;
}

#endif /* ifdef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__ */

/*------------------------------------------------------------------*/

int crypto_interface_random_test_init()
{
  MSTATUS status = ERR_NULL_POINTER;
  int errorCount = 0;

  InitMocanaSetupInfo setupInfo = { 0 };
  /**********************************************************
   *************** DO NOT USE MOC_NO_AUTOSEED ***************
    ***************** in any production code. ****************
    **********************************************************/
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  if (OK != status)
  {
      errorCount = 1;
      goto exit;
  }

#ifdef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
  errorCount += testMbedCtrDrbg (
    kCTR_DRBG_AES256_DF_NoPR, COUNTOF(kCTR_DRBG_AES256_DF_NoPR));
#else
  errorCount += testMocanaCtrDrbg (
    kCTR_DRBG_AES256_DF_NoPR, COUNTOF(kCTR_DRBG_AES256_DF_NoPR));
#endif

exit:
  DIGICERT_free(&gpMocCtx);
  return errorCount;
}
