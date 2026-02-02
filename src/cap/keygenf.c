/*
 * keygenf.c
 *
 * Asymmetric Key Pair Gen functions.
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

/**
@file       keygenf.c
@brief      Mocana Asymmetric Key Pair Gen functions.
@details    Add details here.

@filedoc    keygenf.c
*/
#include "../cap/capasym.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

extern MSTATUS CRYPTO_generateKeyPair (
  MKeyOperator KeyOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  RNGFun RngFun,
  void *pRngFunArg,
  MocAsymKey *ppPubKey,
  MocAsymKey *ppPriKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 localType = 0;
  ubyte4 algoFlag = 0;
  ubyte4 keySize = 0;
  MocAsymKey pNewPub = NULL;
  MocAsymKey pNewPri = NULL;
  MKeyPairGenInfo inputInfo;
  MKeyPairGenResult outputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == KeyOperator) || (NULL == ppPubKey) ||
       (NULL == ppPriKey) )
    goto exit;

  /* Do we support this algorithm? */
  status = KeyOperator (
    NULL, pMocCtx, MOC_ASYM_OP_GET_LOCAL_TYPE, NULL, (void *)&localType, NULL);
  if (OK != status)
    goto exit;

  /* If this is a software implementation, ensure we support the algorithm */
  if (0 != (MOC_LOCAL_TYPE_SW & localType))
  {
    /* Mask off bits to get the algorithm this operator claims to be implementing */
    algoFlag = (localType & MOC_LOCAL_TYPE_COM_MASK) |
              (localType & MOC_LOCAL_TYPE_ALG_MASK);

    status = ERR_CRYPTO_ALGORITHM_UNSUPPORTED;
    switch(algoFlag)
    {
      case MOC_ASYM_ALG_RSA:
        status = ERR_NULL_POINTER;
        if (NULL == pOperatorInfo)
          goto exit;

        status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
        keySize = *((ubyte4 *)pOperatorInfo);
        if ( (1024 != keySize) && (2048 != keySize) &&
             (3072 != keySize) && (4096 != keySize) )
        {
          goto exit;
        }
        break;

      case MOC_ASYM_ALG_DH:
      case MOC_ASYM_ALG_DSA:
      case MOC_ASYM_ALG_ECC_P192:
      case MOC_ASYM_ALG_ECC_P224:
      case MOC_ASYM_ALG_ECC_P256:
      case MOC_ASYM_ALG_ECC_P384:
      case MOC_ASYM_ALG_ECC_P521:
      case MOC_ASYM_ALG_ECC_X25519:
      case MOC_ASYM_ALG_ECC_X448:
      case MOC_ASYM_ALG_ECC_ED25519:
      case MOC_ASYM_ALG_ECC_ED448:
      case MOC_ASYM_ALG_PQC_MLKEM:
      case MOC_ASYM_ALG_PQC_MLDSA:
      case MOC_ASYM_ALG_PQC_FNDSA:
      case MOC_ASYM_ALG_PQC_SLHDSA:
        break;

      default:
        goto exit;
    }
  }

  /* If the addresses where the function will deposit the results contain objects
   * already, free them.
   */
  if (NULL != (*ppPubKey))
  {
    status = CRYPTO_freeMocAsymKey (ppPubKey, ppVlongQueue);
    if (OK != status)
      goto exit;
  }

  if (NULL != (*ppPriKey))
  {
    status = CRYPTO_freeMocAsymKey (ppPriKey, ppVlongQueue);
    if (OK != status)
      goto exit;
  }

  randInfo.RngFun = RngFun;
  randInfo.pRngFunArg = pRngFunArg;
  inputInfo.pOperatorInfo = pOperatorInfo;
  inputInfo.pRandInfo = &randInfo;
  outputInfo.ppPubKey = &pNewPub;
  outputInfo.ppPriKey = &pNewPri;

  status = KeyOperator (
    NULL, pMocCtx, MOC_ASYM_OP_GENERATE, (void *)&inputInfo,
    (void *)&outputInfo, ppVlongQueue);
  if (OK != status)
    goto exit;

  *ppPubKey = pNewPub;
  pNewPub = NULL;

  *ppPriKey = pNewPri;
  pNewPri = NULL;

exit:

  if (NULL != pNewPub)
  {
    CRYPTO_freeMocAsymKey (&pNewPub, ppVlongQueue);
  }
  if (NULL != pNewPri)
  {
    CRYPTO_freeMocAsymKey (&pNewPri, ppVlongQueue);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
