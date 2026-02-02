/*
 * crypto_interface_chacha20_test.c
 *
 * ChaCha20 Encryption Test
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
#include "../../common/initmocana.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../crypto/chacha20.h"
#include "../../crypto/poly1305.h"

#include "../../../unit_tests/unittest.h"

/* for performance testing */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__)
#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__)  || defined(__RTOS_OSX__) */

/* The "global" Digicert context */
static MocCtx gpMocCtx = NULL;

/*------------------------------------------------------------------*/


#ifdef __ENABLE_DIGICERT_CHACHA20__
static const char* kPlainText = "Ladies and Gentlemen of the class of '99: "
                                "If I could offer you only one tip for the future, sunscreen would be it.";
#endif /* __ENABLE_DIGICERT_CHACHA20__ */

/*---------------------------------------------------------------------*/

int crypto_interface_chacha20_test_negative_valid_key_zero_length ()
{
  MSTATUS status = OK;
  int errorCount = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__))

  ChaCha20Ctx *pCtx = NULL;
  ubyte pKey[48] = { 0 };

  InitMocanaSetupInfo setupInfo = { 0 };
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
    
  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
#endif

  pCtx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) pKey, 0, 0);
  errorCount += UNITTEST_TRUE (__MOC_LINE__, (NULL == pCtx) );

exit:

  if (NULL != pCtx)
    DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) (BulkCtx *) &pCtx);

  DIGICERT_free(&gpMocCtx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

#endif

  return ( (OK == status) && (0 == errorCount) ) ? 0 : 1;
}


/* --------------------------------------------------------------- */

int crypto_interface_chacha20_test_negative_null_key_valid_length()
{
  MSTATUS status = OK;
  int errorCount = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__))

  ChaCha20Ctx *pCtx = NULL;

  InitMocanaSetupInfo setupInfo = { 0 };
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
    
  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
#endif

  pCtx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) NULL, 48, 0);
  errorCount += UNITTEST_TRUE (__MOC_LINE__, (NULL == pCtx) );

exit:

  if (NULL != pCtx)
    DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) (BulkCtx *) &pCtx);

  DIGICERT_free(&gpMocCtx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

#endif

  return ( (OK == status) && (0 == errorCount) ) ? 0 : 1;
}


/* --------------------------------------------------------------- */

int crypto_interface_chacha20_test_enabled()
{
  MSTATUS status = OK;
  int errorCount = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__))

  ChaCha20Ctx *pCtx = NULL;
  MocSymCtx pMocSymCtx = NULL;

  const ubyte pBigKey[48] = { 0 };

  InitMocanaSetupInfo setupInfo = { 0 };
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
    
  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
#endif

  status = ERR_NULL_POINTER;
  pCtx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) pBigKey, 48, 0);
  errorCount += UNITTEST_TRUE (__MOC_LINE__, (NULL != pCtx) );
  if (NULL == pCtx)
    goto exit;

  pMocSymCtx = pCtx->pMocSymCtx;

#ifdef __ENABLE_DIGICERT_CHACHA20_MBED__

  status = ERR_INVALID_ARG;
  if (NULL == pMocSymCtx)
  {
    errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
    goto exit;
  }

  if (FALSE == pCtx->enabled)
  {
    errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
    goto exit;
  }

#endif

  status = OK;

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

  DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) (BulkCtx *) &pCtx);
  DIGICERT_free(&gpMocCtx);

#endif

  return ( (OK == status) && (0 == errorCount) ) ? 0 : 1;
}


/* --------------------------------------------------------------- */

int crypto_interface_chacha20_test_encrypt()
{
  MSTATUS status = OK;
  int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__))

  int i;
  BulkCtx ctx = 0;
  sbyte4 resCmp;
  ubyte key[48];
  ubyte nonce[12] =
  {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x4a,
    0x00, 0x00, 0x00, 0x00
  };
  ubyte counter[4] = { 0x01, 0x00, 0x00, 0x00 };

  int ptLen = DIGI_STRLEN((const sbyte*) kPlainText);
  ubyte* ct = 0;
  ubyte expectedCt[] =
  {
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
    0x87, 0x4d,
  };

  InitMocanaSetupInfo setupInfo = { 0 };
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  if (OK != status)
    goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
  {
    retVal = 1;
    goto exit;
  }
    
  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
  {
    retVal = 1;
    goto exit;
  }
#endif

  ct = MALLOC(ptLen);
  retVal += UNITTEST_VALIDPTR(0, ct);
  if (retVal) goto exit;

  DIGI_MEMCPY(ct, kPlainText, ptLen);

  /* the key used in RFC 7539 */
  for (i = 0; i < 32; ++i)
  {
    key[i] = (ubyte) i ;
  }
  DIGI_MEMCPY(key+32, counter, 4);
  DIGI_MEMCPY(key+36, nonce, 12);

  status = ERR_NULL_POINTER;
  ctx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) key, 48, 1);
  retVal += UNITTEST_TRUE (__MOC_LINE__, (NULL != ctx) );
  if (NULL == ctx)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) ctx, ct, ptLen, 1, NULL);
  retVal += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_MEMCMP(ct, expectedCt, (usize)ptLen, &resCmp);

  retVal += UNITTEST_TRUE(0, 0 == resCmp);

  /* Now let's get the plaintext back */

  DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) &ctx);

  status = ERR_NULL_POINTER;
  ctx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) key, 48, 1);
  retVal += UNITTEST_TRUE (__MOC_LINE__, (NULL != ctx) );
  if (NULL == ctx)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) ctx, ct, ptLen, 0, NULL);
  retVal += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_MEMCMP (ct, (ubyte *) kPlainText, (usize)ptLen, &resCmp);

  retVal += UNITTEST_TRUE(0, 0 == resCmp);

exit:
  DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) &ctx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

  FREE( ct);

  DIGICERT_free(&gpMocCtx);

#endif
  return ( (OK == status) && (0 == retVal) ) ? 0 : 1;
}


/* --------------------------------------------------------------- */

int crypto_interface_chacha20_test_encrypt2()
{
  MSTATUS status = OK;
  int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__))

  int i;
  BulkCtx ctx = 0;
  sbyte4 resCmp;
  ubyte key[48];
  ubyte nonce[12] =
  {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x4a,
    0x00, 0x00, 0x00, 0x00
  };
  ubyte counter[4] = { 0x01, 0x00, 0x00, 0x00 };

  ubyte iv[16];

  int ptLen = DIGI_STRLEN((const sbyte*) kPlainText);
  ubyte* ct = 0;
  ubyte expectedCt[] =
  {
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
    0x87, 0x4d,
  };

  InitMocanaSetupInfo setupInfo = { 0 };
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  if (OK != status)
    goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
  {
    retVal = 1;
    goto exit;
  }
    
  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
  {
    retVal = 1;
    goto exit;
  }
#endif

  ct = MALLOC(2*ptLen);
  retVal += UNITTEST_VALIDPTR(0, ct);
  if (retVal) goto exit;

  DIGI_MEMCPY(ct, kPlainText, ptLen);
  DIGI_MEMCPY(ct+ptLen, kPlainText, ptLen);

  /* the key used in RFC 7539 */
  for (i = 0; i < 32; ++i)
  {
    key[i] = (ubyte) i ;
  }
  DIGI_MEMCPY(key+32, counter, 4);
  DIGI_MEMCPY(key+36, nonce, 12);
  DIGI_MEMCPY(iv, counter, 4);
  DIGI_MEMCPY(iv + 4, nonce, 12);

  status = ERR_NULL_POINTER;
  ctx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) key, 48, 1);
  retVal += UNITTEST_TRUE (__MOC_LINE__, (NULL != ctx) );
  if (NULL == ctx)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) ctx, ct, ptLen, 1, iv);
  retVal += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) ctx, ct + ptLen, ptLen, 1, iv);
  retVal += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  //DIGI_MEMCMP(ct, expectedCt, (usize)ptLen, &resCmp);

  //retVal += UNITTEST_TRUE(0, 0 == resCmp);
  DIGI_MEMCPY(iv, counter, 4);
  DIGI_MEMCPY(iv + 4, nonce, 12);

  /* Now let's get the plaintext back */

  DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) &ctx);

  status = ERR_NULL_POINTER;
  ctx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) key, 48, 1);
  retVal += UNITTEST_TRUE (__MOC_LINE__, (NULL != ctx) );
  if (NULL == ctx)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) ctx, ct, ptLen, 0, iv);
  retVal += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) ctx, ct + ptLen, ptLen, 0, iv);
  retVal += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  DIGI_MEMCMP (ct, (ubyte *) kPlainText, (usize)ptLen, &resCmp);
  retVal += UNITTEST_TRUE(0, 0 == resCmp);
  DIGI_MEMCMP (ct + ptLen, (ubyte *) kPlainText, (usize)ptLen, &resCmp);
  retVal += UNITTEST_TRUE(0, 0 == resCmp);

exit:
  DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) &ctx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

  FREE( ct);

  DIGICERT_free(&gpMocCtx);

#endif
  return ( (OK == status) && (0 == retVal) ) ? 0 : 1;
}


/* --------------------------------------------------------------- */

int crypto_interface_chacha20_test_update_indices ()
{
  MSTATUS status = OK;
  ubyte4 errorCount = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__))

  ubyte pBigKey[48];
  ubyte pData[257];
  ubyte pExpectedData[257];

  sbyte4 resCmp;

  ChaCha20Ctx *pCtx = NULL;

  InitMocanaSetupInfo setupInfo = { 0 };
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  if (OK != status)
    goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
    
  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }
#endif

  /* Start with an all-zero key */
  status = DIGI_MEMSET (pBigKey, 0x00, sizeof (pBigKey));
  if (OK != status)
    goto exit;

  /* Fill pData with random bytes */
  status = RANDOM_numberGenerator (g_pRandomContext, pData, sizeof (pData));
  if (OK != status)
    goto exit;

  /* Since ChaCha20 is performed in-place, make a backup of pData */
  status = DIGI_MEMCPY ((void *) pExpectedData, (void *) pData, sizeof (pData));
  if (OK != status)
    goto exit;

  pCtx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) pBigKey, 48, 1);
  errorCount += UNITTEST_TRUE (__MOC_LINE__, (NULL != pCtx) );
  if (NULL == pCtx)
    goto exit;

  /* Now start reading the data in, in weird increments */

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 0, 31, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 31, 65, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 96, 17, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 113, 17, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 130, 33, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 163, 33, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 196, 33, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 229, 28, 1, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Now we have the full ciphertext, so try to decrypt now */

  DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx)  (BulkCtx *) &pCtx);

  pCtx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) pBigKey, 48, 0);
  errorCount += UNITTEST_TRUE (__MOC_LINE__, (NULL != pCtx) );
  if (NULL == pCtx)
    goto exit;

  status = DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData, sizeof (pData), 0, NULL);
  errorCount += UNITTEST_STATUS (__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  /* Now compare the buffers */
  status = DIGI_MEMCMP (pData, pExpectedData, sizeof (pData), &resCmp);
  if (OK != status)
    goto exit;

  errorCount += UNITTEST_TRUE (__MOC_LINE__, (0 == resCmp) );

exit:

  if (NULL != pCtx)
    DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) (BulkCtx *) &pCtx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

  DIGICERT_free(&gpMocCtx);

#endif

  return ( (OK == status) && (0 == errorCount) ) ? 0 : 1;
}
