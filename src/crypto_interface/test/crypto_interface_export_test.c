/*
 * crypto_interface_export_test.c
 *
 * Test cases for export related algorithm checks.
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

static MocCtx gpMocCtx = NULL;

/* Define a new local type for a theoretical new (therefore unsupported)
 * digest algorithm. The creation call for the software operator should
 * fail, while the hardware operator should succeed. */
#define MOC_LOCAL_TYPE_UNSUPPORTED_DIGEST_SW \
  ( MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | 0x00000079 )
#define MOC_LOCAL_TYPE_UNSUPPORTED_DIGEST_HW \
  ( MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_SYM | 0x00000079 )

/* Define a new local type for a new asymmetric algorithm. The creation call for
 * the software operator should fail, while the hardware operator should succeed. */
#define MOC_LOCAL_TYPE_UNSUPPORTED_ASYM_SW \
  ( MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_ASYM | 0x00001900 )
#define MOC_LOCAL_TYPE_UNSUPPORTED_ASYM_HW \
  ( MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_ASYM | 0x00001900 )

#define MOC_LOCAL_TYPE_AES_CBC_IMPL \
    ( MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
      MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CBC )

#define MOC_LOCAL_KEY_RSA_IMPL \
    ( MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | MOC_LOCAL_KEY_RSA )


MOC_EXTERN MSTATUS UnsupportedDigestAlgSw (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  )
{
  MSTATUS status;

  switch(symOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_SYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MOC_LOCAL_TYPE_UNSUPPORTED_DIGEST_SW;
        status = OK;
      }
      break;

    case MOC_SYM_OP_CREATE:
    case MOC_SYM_OP_FREE:
      status = OK;
      break;
  }

exit:
  return status;
}

MOC_EXTERN MSTATUS UnsupportedDigestAlgHw (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  )
{
  MSTATUS status;

  switch(symOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_SYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MOC_LOCAL_TYPE_UNSUPPORTED_DIGEST_HW;
        status = OK;
      }
      break;

    case MOC_SYM_OP_CREATE:
    case MOC_SYM_OP_FREE:
      status = OK;
      break;
  }

exit:
  return status;
}

MOC_EXTERN MSTATUS UnsupportedAsymAlgSw(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;

  switch (keyOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_ASYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_UNSUPPORTED_ASYM_SW;
        status = OK;
      }
      break;

    case MOC_ASYM_OP_CREATE:
    case MOC_ASYM_OP_FREE:
      status = OK;
      break;
  }

exit:
  return status;
}

MOC_EXTERN MSTATUS UnsupportedAsymAlgHw(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;

  switch (keyOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_ASYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_UNSUPPORTED_ASYM_HW;
        status = OK;
      }
      break;

    case MOC_ASYM_OP_CREATE:
    case MOC_ASYM_OP_FREE:
      status = OK;
      break;
  }

exit:
  return status;
}

MOC_EXTERN MSTATUS SomeAesCbcImplSw (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  )
{
  MSTATUS status;

  switch(symOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_SYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MOC_LOCAL_TYPE_AES_CBC_IMPL;
        status = OK;
      }
      break;

    case MOC_SYM_OP_CREATE:
      pMocSymCtx->SymOperator = SomeAesCbcImplSw;
      status = OK;
      break;

    case MOC_SYM_OP_LOAD_KEY:
    case MOC_SYM_OP_FREE:
      status = OK;
      break;
  }

exit:
  return status;
}

MOC_EXTERN MSTATUS SomeRsaImplSw(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;

  switch (keyOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_ASYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *) pOutputInfo) = MOC_LOCAL_KEY_RSA_IMPL;
        status = OK;
      }
      break;

    case MOC_ASYM_OP_CREATE:
    case MOC_ASYM_OP_CREATE_PUB:
    case MOC_ASYM_OP_CREATE_PRI:
      pMocAsymKey->KeyOperator = SomeRsaImplSw;
      pMocAsymKey->localType = MOC_LOCAL_KEY_RSA_IMPL;
      status = OK;
      break;

    case MOC_ASYM_OP_FREE:
    case MOC_ASYM_OP_GENERATE:
    case MOC_ASYM_OP_SET_KEY_DATA:
      status = OK;
      break;
  }

exit:
  return status;
}

int testAsymKeyLengthRestrictions()
{
  MSTATUS status;
  MRsaKeyTemplate keyTemplate = {0};
  MocAsymKey pPubKey = NULL;
  MocAsymKey pPriKey = NULL;
  ubyte pModulus[512] = {0};
  ubyte4 i = 0;
  ubyte4 keyLenBits = 0;
  ubyte4 modulusLenBytes = 0;
  int retVal = 0;

  /* Use a test modulus of all 1s */
  for (i = 0; i < 512; i++)
  {
    pModulus[i] = 0xFF;
  }

  /* Test to make sure we cannot generate a key length other than the
   * supported values */
  for (keyLenBits = 1; keyLenBits < 8192; keyLenBits++)
  {
    status = CRYPTO_generateKeyPair (
      SomeRsaImplSw, (void *)&keyLenBits, gpMocCtx, RANDOM_rngFun,
      g_pRandomContext, &pPubKey, &pPriKey, NULL);
    if ( (1024 == keyLenBits) || (2048 == keyLenBits) ||
         (3072 == keyLenBits) || (4096 == keyLenBits) )
    {
      UNITTEST_STATUS(__MOC_LINE__, status);
      if (OK != status)
      {
        retVal += 1;
      }
    }
    else
    {
      UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_UNSUPPORTED_KEY_LENGTH);
      if (ERR_RSA_UNSUPPORTED_KEY_LENGTH != status)
      {
        retVal += 1;
      }
    }
  }

  /* Test to make sure we cannot set a key with an unsupported modulus length */
  status = CRYPTO_createMocAsymKey(SomeRsaImplSw, NULL, gpMocCtx, 0, &pPubKey);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
  {
    retVal += 1;
    goto exit;
  }

  keyTemplate.pN = (ubyte *)pModulus;

  for (modulusLenBytes = 1; modulusLenBytes < 1024; modulusLenBytes++)
  {
    keyTemplate.nLen = modulusLenBytes;

    status = CRYPTO_setKeyData(pPubKey, (void *)&keyTemplate);
    if ( (128 == modulusLenBytes) || (256 == modulusLenBytes) ||
         (384 == modulusLenBytes) || (512 == modulusLenBytes) )
    {
      UNITTEST_STATUS(__MOC_LINE__, status);
      if (OK != status)
      {
        retVal += 1;
      }
    }
    else
    {
      UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_UNSUPPORTED_KEY_LENGTH);
      if (ERR_RSA_UNSUPPORTED_KEY_LENGTH != status)
      {
        retVal += 1;
      }
    }
  }

exit:

  if (NULL != pPubKey)
  {
    CRYPTO_freeMocAsymKey(&pPubKey, NULL);
  }
  if (NULL != pPriKey)
  {
    CRYPTO_freeMocAsymKey(&pPriKey, NULL);
  }

  return retVal;
}

int testSymKeyLengthRestrictions()
{
  MSTATUS status;
  MocSymCtx pCtx = NULL;
  ubyte pTemp[64] = {0};
  ubyte4 keyLen;
  int retVal = 0;

  status = CRYPTO_createMocSymCtx(SomeAesCbcImplSw, NULL, NULL, &pCtx);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  for (keyLen = 1; keyLen < 64; keyLen++)
  {
    status = CRYPTO_loadSymKey(pCtx, pTemp, keyLen);
    if ( (16 == keyLen) || (24 == keyLen) || (32 == keyLen) )
    {
      UNITTEST_STATUS(__MOC_LINE__, status);
      if (OK != status)
      {
        retVal += 1;
      }
    }
    else
    {
      UNITTEST_INT(__MOC_LINE__, status, ERR_AES_BAD_KEY_LENGTH);
      if (ERR_AES_BAD_KEY_LENGTH != status)
      {
        retVal += 1;
      }
    }
  }

exit:

  if (NULL != pCtx)
  {
    CRYPTO_freeMocSymCtx(&pCtx);
  }

  return retVal;
}

int testExportRestrictions()
{
  MSTATUS status;
  MocSymCtx pCtx = NULL;
  MocAsymKey pKey = NULL;

  status = CRYPTO_createMocSymCtx(UnsupportedDigestAlgSw, NULL, NULL, &pCtx);
  if (OK == status)
  {
    status = CRYPTO_freeMocSymCtx(&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;
  }
  if (ERR_CRYPTO_ALGORITHM_UNSUPPORTED == status)
  {
    status = OK;
  }
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = CRYPTO_createMocSymCtx(UnsupportedDigestAlgHw, NULL, NULL, &pCtx);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = CRYPTO_freeMocSymCtx(&pCtx);
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = CRYPTO_createMocAsymKey (
    UnsupportedAsymAlgSw, NULL, gpMocCtx, 0, &pKey);
  if (ERR_CRYPTO_ALGORITHM_UNSUPPORTED == status)
  {
    status = OK;
  }
  UNITTEST_STATUS(__MOC_LINE__, status);
  if (OK != status)
    goto exit;

  status = CRYPTO_createMocAsymKey (
    UnsupportedAsymAlgHw, NULL, gpMocCtx, 0, &pKey);
  UNITTEST_STATUS(__MOC_LINE__, status);

exit:

  if (NULL != pCtx)
  {
    CRYPTO_freeMocSymCtx(&pCtx);
  }
  if (NULL != pKey)
  {
    CRYPTO_freeMocAsymKey(&pKey, NULL);
  }

  return status;
}

extern int crypto_interface_export_test_init()
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

    errorCount += testExportRestrictions();
    errorCount += testSymKeyLengthRestrictions();
    errorCount += testAsymKeyLengthRestrictions();

exit:
    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
