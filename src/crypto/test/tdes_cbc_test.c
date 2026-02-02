/*
 * tdes_cbc_test.c
 *
 * unit test for tdes.c
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../common/random.h"
#include "../../common/initmocana.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../harness/harness.h"
#include "../../../unit_tests/unittest.h"

/* for performance testing */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (3)
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
                             mContinueTest = 1;          \
                             alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) */

/*------------------------------------------------------------------*/

//#define __ENABLE_TDES_CBC_TEST_DEBUG__

#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/

#define MAX_TDES_TEXT_STRING    1024
#define TEST_BLOCK_SIZE         8


/*------------------------------------------------------------------*/

typedef struct TestDescr
{
    ubyte           key[32];
    ubyte           iv[TEST_BLOCK_SIZE];
    ubyte           text[32];

    /* for test verification */
    ubyte           encrypt[32];
    ubyte           final_iv[TEST_BLOCK_SIZE];

} TestDescr;


/*------------------------------------------------------------------*/

TestDescr tdesCbcTestVectors168[] =
{
    { "0011223300112ee30011223300112233", "00112233", "The eagle flies at midnight.1234", "\xf9\x87\xc8\x74\x40\x49\x5f\x35\xbd\x60\xa7\xa8\x55\xf7\x1d\xfb\x69\x70\xa7\xbc\x5c\xfc\x77\x80\xec\x59\xbb\xbc\x7a\xcf\x7f\x10", "\xec\x59\xbb\xbc\x7a\xcf\x7f\x10" },
    { "ss1d33001122330011223ee0112233dd", "aa11223d", "One test to rule them. Muwhaaaaa", "\xe4\x20\x8f\x9a\x3f\xcb\xff\xc3\xd0\xce\x56\x56\xbd\x0d\x84\x1f\x3a\x5e\x7e\xb4\x03\x01\x99\x58\x33\x61\xcc\x69\x4a\xcd\x85\x65", "\x33\x61\xcc\x69\x4a\xcd\x85\x65" },
    { "011dd330011223xxxff12233001ww230", "bb112233", "They dance at dawn from the West", "\xa6\xf7\x3e\x1c\x3c\xb9\x8a\x8f\xee\xef\xa7\xee\x36\x9e\x63\x07\x97\xe3\xa7\xd2\x26\xf6\x80\xc6\x80\x7b\x9a\x30\xf9\xde\x5c\x82", "\x80\x7b\x9a\x30\xf9\xde\x5c\x82" },
    { "zzz12233001122xxx01122330011qqq3", "0ccc2233", "One last hillarious test vector!", "\x4c\x62\x2b\x5d\xdc\x17\xb8\x99\xea\xec\x47\xf2\xb3\x6a\x42\xe8\x55\x2b\x05\x17\xa6\x20\x37\xab\x3b\xc6\x05\x72\xe0\x40\xf5\xce", "\x3b\xc6\x05\x72\xe0\x40\xf5\xce" }
};


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
static void
dumpHex(char *pMesg, ubyte *pData, ubyte4 length)
{
    ubyte4 index;

    printf("%s[length = %u] =\n", pMesg, length);

    for (index = 0; index < length; index++)
        printf("\\x%02x", pData[index]);

    printf("\n");
}
#endif


/*------------------------------------------------------------------*/

static int
generic_tdes_cbc_test(TestDescr tdesCbcTestVectors[], sbyte4 numVectors, sbyte4 keySize)
{
    ubyte4          retVal = 1;
    BulkCtx         ctx;
    sbyte4          i, cmpResult;
    ubyte*          pKey  = NULL;
    ubyte*          pIvEncrypt = NULL;
    ubyte*          pIvDecrypt = NULL;
    ubyte*          pText = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    /* for harness test... */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 32, TRUE, &pKey)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, TEST_BLOCK_SIZE, TRUE, &pIvEncrypt)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, TEST_BLOCK_SIZE, TRUE, &pIvDecrypt)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, MAX_TDES_TEXT_STRING, TRUE, &pText)))
        goto exit;

    /* timing test can use full buffer initialized to all 0x00 */
    (void) DIGI_MEMSET(pText, 0x00, MAX_TDES_TEXT_STRING);
    retVal = 0;

    for (i = 0; i < numVectors; ++i)
    {
        /* clone data for test */
        DIGI_MEMCPY(pKey,       (ubyte *)(tdesCbcTestVectors[i].key), keySize);
        DIGI_MEMCPY(pIvEncrypt, (ubyte *)(tdesCbcTestVectors[i].iv), TEST_BLOCK_SIZE);
        DIGI_MEMCPY(pIvDecrypt, (ubyte *)(tdesCbcTestVectors[i].iv), TEST_BLOCK_SIZE);
        DIGI_MEMCPY(pText,      (ubyte *)(tdesCbcTestVectors[i].text), 32);

#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
        printf("{\n");
        dumpHex("plain text", pText, 32);
        printf("======\n");
#endif

        /* encrypt test */
        if (NULL == (ctx = Create3DESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = Do3DES(MOC_SYM(hwAccelCtx) ctx, pText, 32, TRUE, pIvEncrypt)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = Delete3DESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
            retVal++;
            continue;
        }

#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
        dumpHex("encrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvEncrypt, TEST_BLOCK_SIZE);
        printf("======\n");
#endif

        /* verify encryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(tdesCbcTestVectors[i].encrypt), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
            printf("generic_tdes_cbc_test: encryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(tdesCbcTestVectors[i].final_iv), pIvEncrypt, TEST_BLOCK_SIZE, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
            printf("generic_tdes_cbc_test: encryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        /* decrypt test */
        if (NULL == (ctx = Create3DESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, FALSE)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = Do3DES(MOC_SYM(hwAccelCtx) ctx, pText, 32, FALSE, pIvDecrypt)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = Delete3DESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
            retVal++;
            continue;
        }

#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
        dumpHex("decrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvDecrypt, TEST_BLOCK_SIZE);
        printf("}\n");
#endif

        /* verify decryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(tdesCbcTestVectors[i].text), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
            printf("generic_tdes_cbc_test: decryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(tdesCbcTestVectors[i].final_iv), pIvDecrypt, TEST_BLOCK_SIZE, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_TDES_CBC_TEST_DEBUG__))
            printf("generic_tdes_cbc_test: decryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }
    }

    /* for linux we do a speed test that will be captured in the logs */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    if (0 == retVal)
    {
        struct tms tstart, tend;
        double diffTime;
        ubyte4 counter;

        /* we are using whatever is there */
        ctx = Create3DESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE);

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        counter = 0;
        while( ALARM_OFF)
        {
            /* process 1024 bytes */
            Do3DES(MOC_SYM(hwAccelCtx) ctx, pText, MAX_TDES_TEXT_STRING, TRUE, pIvEncrypt);
            counter++;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);

        printf("\t3DES_EDE_CBC: %d kbytes in %g seconds of CPU time\n",
               counter, diffTime);
        printf("3DES_EDE_CBC: %g kbytes/second (CPU time) (1 kbyte = 1024 bytes)\n",
               counter/diffTime);

        Delete3DESCtx(MOC_SYM(hwAccelCtx) &ctx);
    }
#endif

exit:

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pKey)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pIvEncrypt)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pIvDecrypt)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pText)))
        goto exit;

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*------------------------------------------------------------------*/

int tdes_cbc_test_vectors168()
{
    return generic_tdes_cbc_test(tdesCbcTestVectors168, (sizeof(tdesCbcTestVectors168)/ sizeof(TestDescr)), 24);
}

int tdes_cbc_pad_test ()
{
  MSTATUS status;
  int retVal;
  sbyte4 cmpResult;
  ubyte4 encryptedDataLen, decryptedDataLen;
  ubyte pKeyData[24];
  ubyte pInitVector[8];
  ubyte pDataToEncrypt[40];
  ubyte pEncryptedData[48];
  ubyte pDecryptedData[48];
  BulkCtx pEncryptor = NULL;
  BulkCtx pDecryptor = NULL;

  InitMocanaSetupInfo setupInfo = {};
  /**********************************************************
    *************** DO NOT USE MOC_NO_AUTOSEED ***************
    ***************** in any production code. ****************
    **********************************************************/
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, NULL);
  if (OK != status)
  {
      retVal = 1;
      goto exit;
  }

  retVal = 0;

  status = RANDOM_numberGenerator (g_pRandomContext, pKeyData, 24);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = RANDOM_numberGenerator (g_pRandomContext, pInitVector, 8);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = RANDOM_numberGenerator (g_pRandomContext, pDataToEncrypt, 40);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  /* Set to all 00 just to get a visual when we overwrite with ciphertext or
   * plaintext.
   */
  status = DIGI_MEMSET ((void *)pEncryptedData, 0, sizeof (pEncryptedData));
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = DIGI_MEMSET ((void *)pDecryptedData, 0, sizeof (pDecryptedData));
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  /* Set the last 5 bytes to 00, because we're going to use input length of 35
   * and we might as well have a visual that shows these bytes are not used.
   */
  pDataToEncrypt[35] = 0;
  pDataToEncrypt[36] = 0;
  pDataToEncrypt[37] = 0;
  pDataToEncrypt[38] = 0;
  pDataToEncrypt[39] = 0;

  status = ERR_CRYPTO;
  pEncryptor = Create3DESCtx (pKeyData, 24, 1);
  if (NULL == pEncryptor)
  {
    retVal += UNITTEST_STATUS (__LINE__, status);
    goto exit;
  }

  pDecryptor = Create3DESCtx (pKeyData, 24, 0);
  if (NULL == pDecryptor)
  {
    retVal += UNITTEST_STATUS (__LINE__, status);
    goto exit;
  }

  status = Do3DesCbcWithPkcs5Pad (
    pEncryptor, (ubyte *)pDataToEncrypt, 35,
    (ubyte *)pEncryptedData, sizeof (pEncryptedData),
    &encryptedDataLen, 1, (ubyte *)pInitVector);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = Do3DesCbcWithPkcs5Pad (
    pDecryptor, (ubyte *)pEncryptedData, encryptedDataLen,
    (ubyte *)pDecryptedData, sizeof (pDecryptedData),
    &decryptedDataLen, 0, (ubyte *)pInitVector);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = 1;
  retVal += UNITTEST_INT (__LINE__, decryptedDataLen, 35);
  if (35 != decryptedDataLen)
    goto exit;

  status = DIGI_MEMCMP (
    (void *)pDecryptedData, (void *)pDataToEncrypt, decryptedDataLen,
    &cmpResult);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = 2;
  retVal += UNITTEST_INT (__LINE__, cmpResult, 0);
  if (0 != cmpResult)
    goto exit;

  /* Encrypt calling Do3DES to make sure we got the correct encrypted data.
   */
  pDataToEncrypt[35] = 5;
  pDataToEncrypt[36] = 5;
  pDataToEncrypt[37] = 5;
  pDataToEncrypt[38] = 5;
  pDataToEncrypt[39] = 5;
  status = Do3DES (
    pEncryptor, (ubyte *)pDataToEncrypt, 40, 1, (ubyte *)pInitVector);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCMP (
    (void *)pEncryptedData, (void *)pDataToEncrypt, 40, &cmpResult);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  status = 3;
  retVal += UNITTEST_INT (__LINE__, cmpResult, 0);
  if (0 != cmpResult)
    goto exit;

  status = OK;

exit:

  if (NULL != pEncryptor)
  {
    status = Delete3DESCtx (&pEncryptor);
    retVal += UNITTEST_STATUS (__LINE__, status);
  }
  if (NULL != pDecryptor)
  {
    status = Delete3DESCtx (&pDecryptor);
    retVal += UNITTEST_STATUS (__LINE__, status);
  }

  DIGICERT_free(NULL);

  return (retVal);
}
