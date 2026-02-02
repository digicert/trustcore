/*
 * crypto_interface_core.c
 *
 * Cryptographic Interface primary functions
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

#include "../crypto/mocasym.h"
#include "../common/initmocana.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
#include "../crypto_interface/tap_extern.h"
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)

/*----------------------------------------------------------------------------*/

static AlgoTableElement *pSymAlgoTable = NULL;
static AlgoTableElement *pKeyAlgoTable = NULL;
static AlgoTableElement *pTapSymAlgoTable = NULL;
static AlgoTableElement *pTapKeyAlgoTable = NULL;
static MocCtx pCryptoInterfaceMocCtx = NULL;
static MocCtx pTapMocCtx = NULL;
static MocCtx pRegisteredMocCtx = NULL;

/*----------------------------------------------------------------------------*/

/* Build the algorithm tables */
MSTATUS CRYPTO_INTERFACE_buildAlgoTables (
  MocCtx pMocCtx,
  AlgoTableElement **ppNewSymAlgoTable,
  AlgoTableElement **ppNewKeyAlgoTable
  );

/* Build the algorithm table for symmetric algorithms */
static MSTATUS CRYPTO_INTERFACE_buildSymAlgoTable (
  MocCtx pMocCtx,
  AlgoTableElement **ppNewSymAlgoTable
  );

/* Build the algorithm table for asymmetric algorithms */
static MSTATUS CRYPTO_INTERFACE_buildKeyAlgoTable (
  MocCtx pMocCtx,
  AlgoTableElement **ppNewKeyAlgoTable
  );

/* Convert a symmetric algorithm flag to an index into the symmetric
 * algorithm table */
static MSTATUS CRYPTO_INTERFACE_symAlgoFlagToTableIndex (
  ubyte4 symAlgoFlag,
  cryptoInterfaceSymAlgo *pTableIndex
  );

/* Convert an asymmetric algorithm flag to an index into the asymmetric
 * algorithm table */
static MSTATUS CRYPTO_INTERFACE_keyAlgoFlagToTableIndex (
  ubyte4 keyAlgoFlag,
  cryptoInterfaceKeyAlgo *pTableIndex
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_registerMocCtx (
  MocCtx pMocCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  /* Make sure the MocCtx is at least not NULL */
  if (NULL == pMocCtx)
    goto exit;

  /* Do we already have a registered MocCtx? */
  status = ERR_UNSUPPORTED_OPERATION;
  if (NULL != pRegisteredMocCtx)
    goto exit;

  /* Register it */
  pRegisteredMocCtx = pMocCtx;
  status = OK;

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_unregisterMocCtx (
  MocCtx pMocCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if (NULL == pMocCtx)
    goto exit;

  /* Do we have a MocCtx registered? */
  status = ERR_UNSUPPORTED_OPERATION;
  if (NULL == pRegisteredMocCtx)
    goto exit;

  /* Is this the MocCtx we originally registered? */
  status = ERR_INVALID_INPUT;
  if (pMocCtx != pRegisteredMocCtx)
    goto exit;

  /* NULL out our reference */
  pRegisteredMocCtx = NULL;
  status = OK;

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_getMocCtx (
  MocCtx *ppMocCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if ( (NULL == ppMocCtx) || (NULL == pCryptoInterfaceMocCtx) )
    goto exit;

  status = OK;
  *ppMocCtx = pCryptoInterfaceMocCtx;

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_getTapMocCtx (
  MocCtx *ppMocCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if ( (NULL == ppMocCtx) || (NULL == pTapMocCtx) )
    goto exit;

  status = OK;
  *ppMocCtx = pTapMocCtx;

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_getRegisteredMocCtx (
  MocCtx *ppMocCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if ( (NULL == ppMocCtx) || (NULL == pRegisteredMocCtx) )
    goto exit;

  status = OK;
  *ppMocCtx = pRegisteredMocCtx;

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_initializeTAPExtern(void)
{
#if defined(__ENABLE_DIGICERT_TAP_EXTERN__)
    MSTATUS status = OK;
    if (g_pFuncPtrGetTapContext == NULL)
    {
        status = DIGICERT_TAPExternInit((void **)&g_pFuncPtrGetTapContext);
    }
    return status;
#else
    return OK;
#endif
}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_freeTAPExtern(void)
{
#if defined(__ENABLE_DIGICERT_TAP_EXTERN__)
    MSTATUS status = OK;
    if (NULL != g_pFuncPtrGetTapContext)
    {
        status = DIGICERT_TAPExternDeinit((void **)&g_pFuncPtrGetTapContext);
    }
    return status;
#else
    return OK;
#endif
}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_initializeCore (
  intBoolean isMultiThreaded
  )
{
  MSTATUS status = OK;
  MocSubCtx *pOpListCtx = NULL;
  MocCtx pMocCtx = NULL;

  ubyte4 digestSwOpCount = 0;
  ubyte4 symSwOpCount = 0;
  ubyte4 keySwOpCount = 0;

#ifdef __ENABLE_DIGICERT_TAP__
  MocCtx pTapMocContext = NULL;
  ubyte4 keyTapOpCount = 1;  /* For sure at least 1 and 4 resp are enabled */
  ubyte4 symTapOpCount = 4;
#endif

  /* Define the list of digest operators */
#ifdef __ENABLE_DIGICERT_DIGEST_OPERATORS__
  MSymOperatorAndInfo pDigestSwOperators[] = {
#ifdef __ENABLE_DIGICERT_MD4_OPERATOR__
    { SymOperatorMd4, NULL },
#endif
#ifdef __ENABLE_DIGICERT_MD5_OPERATOR__
    { SymOperatorMd5, NULL },
#endif
#ifdef __ENABLE_DIGICERT_SHA1_OPERATOR__
    { SymOperatorSha1, NULL },
#endif
#ifdef __ENABLE_DIGICERT_SHA224_OPERATOR__
    { SymOperatorSha224, NULL },
#endif
#ifdef __ENABLE_DIGICERT_SHA256_OPERATOR__
    { SymOperatorSha256, NULL },
#endif
#ifdef __ENABLE_DIGICERT_SHA384_OPERATOR__
    { SymOperatorSha384, NULL },
#endif
#ifdef __ENABLE_DIGICERT_SHA512_OPERATOR__
    { SymOperatorSha512, NULL },
#endif
#ifdef __ENABLE_DIGICERT_SHA3_OPERATOR__
    { SymOperatorSha3, NULL },
#endif
  };
#else
  MSymOperatorAndInfo *pDigestSwOperators = NULL;
#endif

  /* Define the list of symmetric operators */
#ifdef __ENABLE_DIGICERT_SYM_OPERATORS__
  MSymOperatorAndInfo pSymSwOperators[] = {
#ifdef __ENABLE_DIGICERT_ARC4_OPERATOR__
    { SymOperatorArc4, NULL },
#endif
#ifdef __ENABLE_DIGICERT_DES_ECB_OPERATOR__
    { SymOperatorDesEcb, NULL },
#endif
#ifdef __ENABLE_DIGICERT_DES_CBC_OPERATOR__
    { SymOperatorDesCbc, NULL },
#endif
#ifdef __ENABLE_DIGICERT_TDES_ECB_OPERATOR__
    { SymOperatorTDesEcb, NULL },
#endif
#ifdef __ENABLE_DIGICERT_TDES_CBC_OPERATOR__
    { SymOperatorTDesCbc, NULL },
#endif
#ifdef __ENABLE_DIGICERT_HMAC_OPERATOR__
    { SymOperatorHmac, NULL },
#endif
#ifdef __ENABLE_DIGICERT_POLY1305_OPERATOR__
    { SymOperatorPoly1305, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_ECB_OPERATOR__
    { SymOperatorAesEcb, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_CBC_OPERATOR__
    { SymOperatorAesCbc, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_OFB_OPERATOR__
    { SymOperatorAesOfb, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_CTR_OPERATOR__
    { SymOperatorAesCtr, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_CFB128_OPERATOR__
    { SymOperatorAesCfb128, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_CFB1_OPERATOR__
    { SymOperatorAesCfb1, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_GCM_OPERATOR__
    { SymOperatorAesGcm, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_CMAC_OPERATOR__
    { SymOperatorAesCmac, NULL },
#endif
#ifdef __ENABLE_DIGICERT_AES_XTS_OPERATOR__
    { SymOperatorAesXts, NULL },
#endif
#ifdef __ENABLE_DIGICERT_CTR_DRBG_AES_OPERATOR__
    { SymOperatorCtrDrbgAes, NULL },
#endif
#ifdef __ENABLE_DIGICERT_CHACHA20_OPERATOR__
    { SymOperatorChaCha20, NULL },
#endif
#ifdef __ENABLE_DIGICERT_CHACHA_POLY_OPERATOR__
    { SymOperatorChaChaPoly, NULL },
#endif
#ifdef __ENABLE_DIGICERT_BLOWFISH_OPERATOR__
    { SymOperatorBlowfish, NULL },
#endif
#ifdef __ENABLE_DIGICERT_HMAC_KDF_OPERATOR__
    { SymOperatorHmacKdf, NULL },
#endif
#ifdef __ENABLE_DIGICERT_PKCS5_OPERATOR__
    { SymOperatorPkcs5Pbe, NULL },
#endif
  };
#else
  MSymOperatorAndInfo *pSymSwOperators = NULL;
#endif

  /* Define the list of key operators */
#ifdef __ENABLE_DIGICERT_KEY_OPERATORS__
  MKeyOperatorAndInfo pKeySwOperators[] = {
#ifdef __ENABLE_DIGICERT_DH_OPERATOR__
    { KeyOperatorDh, NULL },
#endif
#ifdef __ENABLE_DIGICERT_RSA_OPERATOR__
    { KeyOperatorRsa, NULL },
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192_OPERATOR__
    { KeyOperatorEccNistP192, NULL },
#endif
#ifdef __ENABLE_DIGICERT_ECC_P224_OPERATOR__
    { KeyOperatorEccNistP224, NULL },
#endif
#ifdef __ENABLE_DIGICERT_ECC_P256_OPERATOR__
    { KeyOperatorEccNistP256, NULL },
#endif
#ifdef __ENABLE_DIGICERT_ECC_P384_OPERATOR__
    { KeyOperatorEccNistP384, NULL },
#endif
#ifdef __ENABLE_DIGICERT_ECC_P521_OPERATOR__
    { KeyOperatorEccNistP521, NULL },
#endif
#ifdef __ENABLE_DIGICERT_QS_KYBER_OPERATOR__
    { KeyOperatorKemQSKyber, NULL},
#endif
#ifdef __ENABLE_DIGICERT_QS_DILITHIUM_OPERATOR__
    { KeyOperatorSigQSDilithium, NULL},
#endif
#ifdef __ENABLE_DIGICERT_QS_FALCON_OPERATOR__
    { KeyOperatorSigQSFalcon, NULL},
#endif
#ifdef __ENABLE_DIGICERT_QS_SPHINCS_OPERATOR__
    { KeyOperatorSigQSSphincs, NULL},
#endif
  };
#else
  MKeyOperatorAndInfo *pKeySwOperators = NULL;
#endif

  /* Define the List of Hardware Operators */
#ifdef __ENABLE_DIGICERT_TAP__
  MKeyOperatorAndInfo pKeyTapOperators[] =
  {
    { KeyOperatorRsaTap, NULL },
#ifdef __ENABLE_DIGICERT_ECC__
    { KeyOperatorEccTap, NULL }
#endif
  };

  MSymOperatorAndInfo pSymTapOperators[] =
  {
    { MAesTapOperator, NULL},
    { MDesTapOperator, NULL},
    { MTDesTapOperator, NULL},
    { MHmacTapOperator, NULL},
  };
#endif

  /* Are we already initialized? */
  if (NULL != pCryptoInterfaceMocCtx)
    goto exit;  /* status = OK still */

  /* Get the total numbers of each operator type */
#ifdef __ENABLE_DIGICERT_DIGEST_OPERATORS__
  digestSwOpCount = 0 
#ifdef __ENABLE_DIGICERT_MD4_OPERATOR__
                  + 1
#endif
#ifdef __ENABLE_DIGICERT_MD5_OPERATOR__
                  + 1
#endif
#ifdef __ENABLE_DIGICERT_SHA1_OPERATOR__
                  + 1
#endif
#ifdef __ENABLE_DIGICERT_SHA224_OPERATOR__
                  + 1
#endif
#ifdef __ENABLE_DIGICERT_SHA256_OPERATOR__
                  + 1
#endif
#ifdef __ENABLE_DIGICERT_SHA384_OPERATOR__
                  + 1
#endif
#ifdef __ENABLE_DIGICERT_SHA512_OPERATOR__
                  + 1
#endif
#ifdef __ENABLE_DIGICERT_SHA3_OPERATOR__
                  + 1
#endif
  ;
#endif /* __ENABLE_DIGICERT_DIGEST_OPERATORS__ */

#ifdef __ENABLE_DIGICERT_SYM_OPERATORS__
  symSwOpCount = 0
#ifdef __ENABLE_DIGICERT_ARC4_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_DES_ECB_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_DES_CBC_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_TDES_ECB_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_TDES_CBC_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_HMAC_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_POLY1305_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_ECB_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_CBC_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_OFB_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_CTR_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_CFB128_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_CFB1_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_GCM_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_CMAC_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_AES_XTS_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_CTR_DRBG_AES_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_CHACHA20_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_CHACHA_POLY_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_BLOWFISH_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_HMAC_KDF_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_PKCS5_OPERATOR__
               + 1
#endif
  ;
#endif /* __ENABLE_DIGICERT_SYM_OPERATORS__ */

#ifdef __ENABLE_DIGICERT_KEY_OPERATORS__
  keySwOpCount = 0
#ifdef __ENABLE_DIGICERT_DH_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_RSA_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_ECC_P224_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_ECC_P256_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_ECC_P384_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_ECC_P521_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_QS_KYBER_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_QS_DILITHIUM_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_QS_FALCON_OPERATOR__
               + 1
#endif
#ifdef __ENABLE_DIGICERT_QS_SPHINCS_OPERATOR__
               + 1
#endif
  ;
#endif /* __ENABLE_DIGICERT_KEY_OPERATORS__ */

#if defined(__ENABLE_DIGICERT_TAP__) && defined (__ENABLE_DIGICERT_ECC__)
  keyTapOpCount += 1;
#endif

  /* Create the MocCtx for the Crypto Interface */
  status = CreateMocCtx (isMultiThreaded, &pMocCtx);
  if (OK != status)
    goto exit;

  status = MBuildOpListCtx (
    pDigestSwOperators, digestSwOpCount,
    pSymSwOperators, symSwOpCount,
    pKeySwOperators, keySwOpCount,
    &pOpListCtx);
  if (OK != status)
    goto exit;

  status = MocLoadNewSubCtx (pMocCtx, &pOpListCtx);
  if (OK != status)
    goto exit;

  /* Build the algorithm tables */
  status = CRYPTO_INTERFACE_buildAlgoTables (
    pMocCtx, &pSymAlgoTable, &pKeyAlgoTable);
  if (OK != status)
    goto exit;

  pCryptoInterfaceMocCtx = pMocCtx;
  pMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_TAP__
  /* Free the oplistctx for reuse */
  MSubCtxOpListFree ((struct MocSubCtx **)&pOpListCtx);

  /* Create a new MocCtx for hardware operators */
  status = CreateMocCtx (isMultiThreaded, &pTapMocContext);
  if (OK != status)
    goto exit;

  status = MBuildOpListCtx (
    NULL, 0, pSymTapOperators, symTapOpCount, pKeyTapOperators, keyTapOpCount, &pOpListCtx);
  if (OK != status)
    goto exit;

  status = MocLoadNewSubCtx (pTapMocContext, &pOpListCtx);
  if (OK != status)
    goto exit;

  /* Build the algorithm tables */
  status = CRYPTO_INTERFACE_buildAlgoTables (
    pTapMocContext, &pTapSymAlgoTable, &pTapKeyAlgoTable);
  if (OK != status)
    goto exit;

  pTapMocCtx = pTapMocContext;
  pTapMocContext = NULL;
#endif

exit:

  if (NULL != pOpListCtx)
  {
    MSubCtxOpListFree ((struct MocSubCtx **)&pOpListCtx);
  }
  if (NULL != pMocCtx)
  {
    FreeMocCtx (&pMocCtx);
  }

#ifdef __ENABLE_DIGICERT_TAP__
  if (NULL != pTapMocContext)
  {
    FreeMocCtx (&pTapMocContext);
  }
#endif

  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_uninitializeCore()
{
  MSTATUS status = OK;

  /* If we have a MocCtx, free it now */
  FreeMocCtx(&pCryptoInterfaceMocCtx);
  pCryptoInterfaceMocCtx = NULL;

  /* If we have a MocCtx for TAP operators, free it now */
  FreeMocCtx(&pTapMocCtx);
  pTapMocCtx = NULL;

  /* Free the algorithm tables */
  if (NULL != pSymAlgoTable)
  {
    DIGI_FREE((void **)&pSymAlgoTable);
  }
  if (NULL != pKeyAlgoTable)
  {
    DIGI_FREE((void **)&pKeyAlgoTable);
  }
  if (NULL != pTapSymAlgoTable)
  {
    DIGI_FREE((void **)&pTapSymAlgoTable);
  }
  if (NULL != pTapKeyAlgoTable)
  {
    DIGI_FREE((void **)&pTapKeyAlgoTable);
  }

  return (status);
}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_buildAlgoTables (
  MocCtx pMocCtx,
  AlgoTableElement **ppNewSymAlgoTable,
  AlgoTableElement **ppNewKeyAlgoTable
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if (NULL == pMocCtx)
    goto exit;

  status = CRYPTO_INTERFACE_buildSymAlgoTable(pMocCtx, ppNewSymAlgoTable);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_buildKeyAlgoTable(pMocCtx, ppNewKeyAlgoTable);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_buildKeyAlgoTable (
  MocCtx pMocCtx,
  AlgoTableElement **ppNewKeyAlgoTable
  )
{
  MSTATUS status;
  cryptoInterfaceKeyAlgo tableIndex;
  ubyte4 index, localType, algoFlag, listCount;
  AlgoTableElement *pNewTable = NULL;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MocAsymKey pTemp = NULL;
  MKeyOperatorAndInfo *pKeyOperators = NULL;
  MocAsymmetricKey temp = { 0, NULL, NULL, NULL };

  status = ERR_NULL_POINTER;
  if ( (NULL == pMocCtx) || (NULL == ppNewKeyAlgoTable) )
    goto exit;

  /* Do we already have a table? if so free it and build a new one */
  if (NULL != (*ppNewKeyAlgoTable))
  {
    status = DIGI_FREE((void **)ppNewKeyAlgoTable);
    if (OK != status)
      goto exit;
  }

  /* Allocate a new table for asymmetric algorithms, one element for each
   * algorithm we support. Each element contains a value indicating if there
   * is a valid alternate implementation for that algorithm, and if it is
   * valid then another value for the index into the MocCtx at which that
   * implementing operator can be found */
  status = DIGI_CALLOC (
    (void **)&pNewTable, MOC_CRYPTO_INTERFACE_NUM_KEY_ALGOS, sizeof(AlgoTableElement));
  if (OK != status)
    goto exit;

  /* Get the list of asymmetric operators */
  status = MocAcquireSubCtxRef (
    pMocCtx, MOC_SUB_CTX_TYPE_OP_LIST, &pSubCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pSubCtx->pLocalCtx);
  pKeyOperators = pOpList->pKeyOperators;
  listCount = pOpList->keyOperatorCount;

  /* Loop through each asymmetric operator */
  for (index = 0; index < listCount; ++index)
  {
    if (NULL != pKeyOperators[index].KeyOperator)
    {
      /* Retrieve the local type from the operator, all operators should
       * support this, so any failure is an error */
      status = pKeyOperators[index].KeyOperator (
        &temp, pMocCtx, MOC_ASYM_OP_GET_LOCAL_TYPE, NULL, (void *)&localType, NULL);
      if (OK != status)
        goto exit;

      /* Attempt to create the object */
      status = CRYPTO_createMocAsymKey (
        pKeyOperators[index].KeyOperator, pKeyOperators[index].pOperatorInfo,
        pMocCtx, 0, &pTemp);
      if (OK == status)
      {
        /* We were able to create this object successfully, get the algorithm
         * flag by masking off some bits */
        algoFlag = (localType & MOC_LOCAL_TYPE_COM_MASK) |
                   (localType & MOC_LOCAL_TYPE_ALG_MASK);

        /* Get the index into the algorithm table from the algorithm flag */
        status = CRYPTO_INTERFACE_keyAlgoFlagToTableIndex(algoFlag, &tableIndex);

        /* If this algorithm was already marked as enabled, leave it as is. In
         * the case of multiple active operators for a single algorithm,
         * we always want to leave the index at the first one found in the MocCtx. */
        if ( (OK == status) && (0 == pNewTable[tableIndex].algoEnabled) )
        {
          /* This algorithm has a valid alternate implementation, mark its status
           * and the index at which the implementating operator was found */
          pNewTable[tableIndex].algoEnabled = 1;
          pNewTable[tableIndex].mocCtxIndex = index;
        }

        CRYPTO_freeMocAsymKey(&pTemp, NULL);
      }
    }
  }

  /* Set the newly created table */
  status = OK;
  *ppNewKeyAlgoTable = pNewTable;
  pNewTable = NULL;

exit:

  if (NULL != pNewTable)
  {
    DIGI_FREE((void **)&pNewTable);
  }
  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return status;

}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_buildSymAlgoTable (
  MocCtx pMocCtx,
  AlgoTableElement **ppNewSymAlgoTable
  )
{
  MSTATUS status;
  cryptoInterfaceSymAlgo tableIndex;
  ubyte4 index, localType, algoFlag, listCount;
  AlgoTableElement *pNewTable = NULL;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MSymOperatorAndInfo *pSymOperators;
  MocSymCtx pTemp = NULL;
  MocSymContext temp = { 0, NULL, NULL, 0 };

  status = ERR_NULL_POINTER;
  if ( (NULL == pMocCtx) || (NULL == ppNewSymAlgoTable) )
    goto exit;

  /* Do we already have a table? if so free it and build a new one */
  if (NULL != (*ppNewSymAlgoTable))
  {
    status = DIGI_FREE((void **)ppNewSymAlgoTable);
    if (OK != status)
      goto exit;
  }

  /* Allocate a new table for symmetric algorithms, one element for each
   * algorithm we support. Each element contains a value indicating if there
   * is a valid alternate implementation for that algorithm, and if it is
   * valid then another value for the index into the MocCtx at which that
   * implementing operator can be found */
  status = DIGI_CALLOC (
    (void **)&pNewTable, MOC_CRYPTO_INTERFACE_NUM_SYM_ALGOS, sizeof(AlgoTableElement));
  if (OK != status)
    goto exit;

  /* Get the list of symmetric operators */
  status = MocAcquireSubCtxRef (
    pMocCtx, MOC_SUB_CTX_TYPE_OP_LIST, &pSubCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pSubCtx->pLocalCtx);
  pSymOperators = pOpList->pSymOperators;
  listCount = pOpList->symOperatorCount;

  /* Loop through each symmetric operator */
  for (index = 0; index < listCount; ++index)
  {
    if (NULL != pSymOperators[index].SymOperator)
    {
      /* Retrieve the local type from the operator, all operators should
       * support this, so any failure is an error */
      status = pSymOperators[index].SymOperator (
        &temp, pMocCtx, MOC_SYM_OP_GET_LOCAL_TYPE, NULL, (void *)&localType);
      if (OK != status)
        goto exit;

      /* Attempt to create the object */
      status = CRYPTO_createMocSymCtx (
        pSymOperators[index].SymOperator, pSymOperators[index].pOperatorInfo,
        pMocCtx, &pTemp);
      if (OK == status)
      {
        /* We were able to create this object successfully, get the algorithm
         * flag by masking off some bits */
        algoFlag = (localType & MOC_LOCAL_TYPE_COM_MASK) |
                   (localType & MOC_LOCAL_TYPE_ALG_MASK);

        /* Get the index into the algorithm table from the algorithm flag */
        status = CRYPTO_INTERFACE_symAlgoFlagToTableIndex(algoFlag, &tableIndex);

        /* If this algorithm was already marked as enabled, leave it as is. In
         * the case of multiple active operators for a single algorithm,
         * we always want to leave the index at the first one found in the MocCtx. */
        if ( (OK == status) && (0 == pNewTable[tableIndex].algoEnabled) )
        {
          /* This algorithm has a valid alternate implementation, mark its status
           * and the index at which the implementating operator was found */
          pNewTable[tableIndex].algoEnabled = 1;
          pNewTable[tableIndex].mocCtxIndex = index;
        }

        CRYPTO_freeMocSymCtx(&pTemp);
      }
    }
  }

  /* Set the newly created table */
  status = OK;
  *ppNewSymAlgoTable = pNewTable;
  pNewTable = NULL;

exit:

  if (NULL != pNewTable)
  {
    DIGI_FREE((void **)&pNewTable);
  }
  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_createAndLoadSymKey (
  ubyte4 algoIndex,
  void *pOperatorInfo,
  ubyte *pKeyMaterial,
  ubyte4 keyMaterialLen,
  MocSymCtx *ppNewSymCtx
  )
{
  MSTATUS status;
  MocSymCtx pNewCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppNewSymCtx) || (NULL == pCryptoInterfaceMocCtx) )
    goto exit;

  status = CRYPTO_getMocSymObjectFromIndex (
    algoIndex, pCryptoInterfaceMocCtx, pOperatorInfo, &pNewCtx);
  if (OK != status)
    goto exit;

  /* If key data was provided, load it now */
  if ( (NULL != pKeyMaterial) && (0 < keyMaterialLen) )
  {
    status = CRYPTO_loadSymKey (pNewCtx, pKeyMaterial, keyMaterialLen);
    if (OK != status)
      goto exit;
  }

  *ppNewSymCtx = pNewCtx;
  pNewCtx = NULL;

exit:

  if (NULL != pNewCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewCtx);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_freeAsymKeys (
  void **ppKeyShell,
  MocAsymKey pPublicKey,
  MocAsymKey pPrivateKey
  )
{
  MSTATUS status, fStatus;
  ubyte4 sharedKeyData = FALSE;

  status = OK;

  if ( (NULL == pPublicKey) || (NULL == pPrivateKey) ||
       (0 == (MOC_LOCAL_TYPE_TAP & pPublicKey->localType)) )
  {
    status = CRYPTO_freeMocAsymKey(&pPrivateKey, NULL);

    fStatus = CRYPTO_freeMocAsymKey(&pPublicKey, NULL);
    if (OK == status)
      status = fStatus;
  }
  else
  {
    /* The underlying TAP key doesnt have the concept of separate public
     * private pairs, its just one key that represents either a single
     * public key or a private/public pair as a single entity. When loading
     * a private MocAsymKey from a generation or deserialization, we will
     * call on the operator to get a public MocAsymKey from the private.
     * The TAP operators implement this in a special way, the public
     * MocAsymKey simply has a reference to the same local key data used
     * by the private key. In this case we want to make sure the TAP key
     * is not accidentally freed twice, so after the private key has been
     * freed (thus freeing the underlying TAP key) we NULL out the public
     * key reference to that local key data. If the TAP key was originally
     * public instead, the private key allocated its own structure for the
     * local key data (which is likely empty). In that case we dont want
     * to NULL out the local data of the public key since it is a separate
     * allocation. In short, if the public key is sharing the same local
     * key data with the private key, NULL out its reference after freeing
     * the private key. */
    if (pPrivateKey->pKeyData == pPublicKey->pKeyData)
    {
      sharedKeyData = TRUE;
    }

    status = CRYPTO_freeMocAsymKey(&pPrivateKey, NULL);

    if (TRUE == sharedKeyData)
    {
      pPublicKey->pKeyData = NULL;
    }

    fStatus = CRYPTO_freeMocAsymKey(&pPublicKey, NULL);
    if (OK == status)
      status = fStatus;
  }

  fStatus = DIGI_FREE((void **)ppKeyShell);
  if (OK == status)
    status = fStatus;

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_checkAsymAlgoStatus (
  cryptoInterfaceKeyAlgo keyAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  )
{
  MSTATUS status;
  ubyte4 algoStatus;

  status = ERR_NULL_POINTER;
  if (NULL == pAlgoStatus)
    goto exit;

  algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;

  /* Is this algorithm one we support? */
  status = ERR_INVALID_INPUT;
  if (MOC_CRYPTO_INTERFACE_NUM_KEY_ALGOS <= (ubyte4) keyAlgo)
    goto exit;

  /* Do we have a MocCtx? */
  status = OK;
  if (NULL == pCryptoInterfaceMocCtx)
    goto exit;

  /* Do we have an algorithm table? */
  if (NULL == pKeyAlgoTable)
    goto exit;

  algoStatus = pKeyAlgoTable[keyAlgo].algoEnabled;

  /* Give the index back as well if requested */
  if (NULL != pAlgoIndex)
  {
    *pAlgoIndex = pKeyAlgoTable[keyAlgo].mocCtxIndex;
  }

exit:

  if (NULL != pAlgoStatus)
  {
    *pAlgoStatus = algoStatus;
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_checkTapAsymAlgoStatus (
  cryptoInterfaceKeyAlgo keyAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  )
{
  MSTATUS status;
  ubyte4 algoStatus;

  status = ERR_NULL_POINTER;
  if (NULL == pAlgoStatus)
    goto exit;

  algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;

  /* Is this algorithm one we support? */
  status = ERR_INVALID_INPUT;
  if (MOC_CRYPTO_INTERFACE_NUM_KEY_ALGOS <= (ubyte) keyAlgo)
    goto exit;

  /* Do we have a MocCtx? */
  status = OK;
  if (NULL == pTapMocCtx)
    goto exit;

  /* Do we have an algorithm table? */
  if (NULL == pTapKeyAlgoTable)
    goto exit;

  algoStatus = pTapKeyAlgoTable[keyAlgo].algoEnabled;

  /* Give the index back as well if requested */
  if (NULL != pAlgoIndex)
  {
    *pAlgoIndex = pTapKeyAlgoTable[keyAlgo].mocCtxIndex;
  }

exit:

  if (NULL != pAlgoStatus)
  {
    *pAlgoStatus = algoStatus;
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_checkSymAlgoStatus (
  cryptoInterfaceSymAlgo symAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  )
{
  MSTATUS status;
  ubyte4 algoStatus;

  status = ERR_NULL_POINTER;
  if (NULL == pAlgoStatus)
    goto exit;

  algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;

  /* Is this algorithm one we support? */
  status = ERR_INVALID_INPUT;
  if (MOC_CRYPTO_INTERFACE_NUM_SYM_ALGOS <= (ubyte) symAlgo)
    goto exit;

  /* Do we have a MocCtx? */
  status = OK;
  if (NULL == pCryptoInterfaceMocCtx)
    goto exit;

  /* Do we have an algorithm table? */
  if (NULL == pSymAlgoTable)
    goto exit;

  algoStatus = pSymAlgoTable[symAlgo].algoEnabled;

  /* Give the index back as well if requested */
  if (NULL != pAlgoIndex)
  {
    *pAlgoIndex = pSymAlgoTable[symAlgo].mocCtxIndex;
  }

exit:

  if (NULL != pAlgoStatus)
  {
    *pAlgoStatus = algoStatus;
  }

  return status;

}

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_checkTapSymAlgoStatus (
  cryptoInterfaceSymAlgo symAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  )
{
  MSTATUS status;
  ubyte4 algoStatus;

  status = ERR_NULL_POINTER;
  if (NULL == pAlgoStatus)
    goto exit;

  algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;

  /* Is this algorithm one we support? */
  status = ERR_INVALID_INPUT;
  if (MOC_CRYPTO_INTERFACE_NUM_SYM_ALGOS <= (ubyte) symAlgo)
    goto exit;

  /* Do we have a MocCtx? */
  status = OK;
  if (NULL == pTapMocCtx)
    goto exit;

  /* Do we have an algorithm table? */
  if (NULL == pTapSymAlgoTable)
    goto exit;

  algoStatus = pTapSymAlgoTable[symAlgo].algoEnabled;

  /* Give the index back as well if requested */
  if (NULL != pAlgoIndex)
  {
    *pAlgoIndex = pTapSymAlgoTable[symAlgo].mocCtxIndex;
  }

exit:

  if (NULL != pAlgoStatus)
  {
    *pAlgoStatus = algoStatus;
  }

  return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_keyAlgoFlagToTableIndex (
  ubyte4 keyAlgoFlag,
  cryptoInterfaceKeyAlgo *pTableIndex
  )
{
  MSTATUS status;
  cryptoInterfaceKeyAlgo tableIndex;

  status = ERR_NULL_POINTER;
  if (NULL == pTableIndex)
    goto exit;

  status = ERR_INVALID_INPUT;
  switch(keyAlgoFlag)
  {
    case MOC_ASYM_ALG_RSA:
      tableIndex = moc_alg_rsa;
      break;

    case MOC_ASYM_ALG_DSA:
      tableIndex = moc_alg_dsa;
      break;

    case MOC_ASYM_ALG_DH:
      tableIndex = moc_alg_dh;
      break;

    case MOC_ASYM_ALG_ECC_P192:
      tableIndex = moc_alg_ecc_p192;
      break;

    case MOC_ASYM_ALG_ECC_P224:
      tableIndex = moc_alg_ecc_p224;
      break;

    case MOC_ASYM_ALG_ECC_P256:
      tableIndex = moc_alg_ecc_p256;
      break;

    case MOC_ASYM_ALG_ECC_P384:
      tableIndex = moc_alg_ecc_p384;
      break;

    case MOC_ASYM_ALG_ECC_P521:
      tableIndex = moc_alg_ecc_p521;
      break;

    case MOC_ASYM_ALG_ECC_X25519:
      tableIndex = moc_alg_ecc_x25519;
      break;

    case MOC_ASYM_ALG_ECC_X448:
      tableIndex = moc_alg_ecc_x448;
      break;

    case MOC_ASYM_ALG_ECC_ED25519:
      tableIndex = moc_alg_ecc_ed25519;
      break;

    case MOC_ASYM_ALG_ECC_ED448:
      tableIndex = moc_alg_ecc_ed448;
      break;

    case MOC_ASYM_ALG_PQC_MLKEM:
      tableIndex = moc_alg_qs_kem_mlkem;
      break;
    
    case MOC_ASYM_ALG_PQC_MLDSA:
      tableIndex = moc_alg_qs_sig_mldsa;
      break;

    case MOC_ASYM_ALG_PQC_FNDSA:
      tableIndex = moc_alg_qs_sig_fndsa;
      break;
    
    case MOC_ASYM_ALG_PQC_SLHDSA:
      tableIndex = moc_alg_qs_sig_slhdsa;
      break;

    default:
      goto exit;
  }

  status = OK;
  *pTableIndex = tableIndex;

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_symAlgoFlagToTableIndex (
  ubyte4 symAlgoFlag,
  cryptoInterfaceSymAlgo *pTableIndex
  )
{
  MSTATUS status;
  ubyte4 index;

  status = ERR_NULL_POINTER;
  if (NULL == pTableIndex)
    goto exit;

  status = ERR_INVALID_INPUT;
  for (index = 0; index < MOC_CRYPTO_INTERFACE_NUM_SYM_ALGOS; ++index)
  {
    if (symAlgoFlag == pSupportedSymAlgos[index])
    {
      status = OK;
      break;
    }
  }
  /* If status is not OK by this point, we cannot find the flag-index pair */
  if (OK != status)
    goto exit;

  *pTableIndex = (cryptoInterfaceSymAlgo) index;

exit:
  return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_getIv(
  MOC_SYM(hwAccelDescr hwAccelCtx) MocSymCtx pCtx,
  ubyte *pIv
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MSymOperatorData operatorData = {0};

  if (NULL == pCtx)
    goto exit;

  operatorData.pData = pIv;
  status = CRYPTO_getSymOperatorData(pCtx, NULL, &operatorData);

exit:
  return status;
}

#endif /* if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) */
