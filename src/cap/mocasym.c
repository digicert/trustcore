/*
 * mocasym.c
 *
 * Mocana Asymmetric Key functions.
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
@file       mocasym.c
@brief      Mocana Asymmetric Key functions.
@details    Add details here.

@filedoc    mocasym.c
*/
#include "../cap/capasym.h"
#include "../common/serialcommon.h"
#include "../common/initmocana.h"
#include "../common/base64.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_priv.h"
#endif

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

MOC_EXTERN_DATA_DEF const ubyte4 pSupportedAsymAlgos[MOC_NUM_SUPPORTED_ASYM_ALGOS] =
{
  MOC_ASYM_ALG_DH,
  MOC_ASYM_ALG_RSA,
  MOC_ASYM_ALG_DSA,
  MOC_ASYM_ALG_ECC_P192,
  MOC_ASYM_ALG_ECC_P224,
  MOC_ASYM_ALG_ECC_P256,
  MOC_ASYM_ALG_ECC_P384,
  MOC_ASYM_ALG_ECC_P521,
  MOC_ASYM_ALG_ECC_X25519,
  MOC_ASYM_ALG_ECC_X448,
  MOC_ASYM_ALG_ECC_ED25519,
  MOC_ASYM_ALG_ECC_ED448,
  MOC_ASYM_ALG_PQC_MLKEM,
  MOC_ASYM_ALG_PQC_MLDSA,
  MOC_ASYM_ALG_PQC_FNDSA,
  MOC_ASYM_ALG_PQC_SLHDSA
};

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_createMocAsymKey (
  MKeyOperator KeyOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  ubyte4 typeFlag,
  MocAsymKey *ppNewKey
  )
{
  MSTATUS status;
  ubyte4 flag, i;
  ubyte4 localType = 0;
  ubyte4 algoFlag = 0;
  MocAsymKey pKey = NULL;
  keyOperation keyOp = MOC_ASYM_OP_CREATE;

  /* Init to 0 to indicate we do not release the reference to the MocCtx.
   */
  flag = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == KeyOperator) || (NULL == ppNewKey) || (NULL == pMocCtx) )
    goto exit;

  *ppNewKey = NULL;

  if (MOC_ASYM_KEY_TYPE_PUBLIC == typeFlag)
  {
    keyOp = MOC_ASYM_OP_CREATE_PUB;
  }
  else if (MOC_ASYM_KEY_TYPE_PRIVATE == typeFlag)
  {
    keyOp = MOC_ASYM_OP_CREATE_PRI;
  }

  /* Allocate the Key shell.
   */
  status = DIGI_CALLOC ((void **)&pKey, sizeof (MocAsymmetricKey), 1);
  if (OK != status)
    goto exit;

  /* Get the local type from the provided operator */
  status = KeyOperator (
    pKey, pMocCtx, MOC_ASYM_OP_GET_LOCAL_TYPE, NULL, (void *)&localType, NULL);
  if (OK != status)
    goto exit;

  /* If this is a software implementation, ensure we support the algorithm */
  if (0 != (MOC_LOCAL_TYPE_SW & localType))
  {
    /* Mask off bits to get the algorithm this operator claims to be implementing */
    algoFlag = (localType & MOC_LOCAL_TYPE_COM_MASK) |
              (localType & MOC_LOCAL_TYPE_ALG_MASK);

    /* Check with the list of approved algorithms */
    status = ERR_CRYPTO_ALGORITHM_UNSUPPORTED;
    for (i = 0; i < MOC_NUM_SUPPORTED_ASYM_ALGOS; i++)
    {
      if (algoFlag == pSupportedAsymAlgos[i])
      {
        status = OK;
        break;
      }
    }

    /* If status is not OK, we dont support that algorithm */
    if (OK != status)
      goto exit;
  }

  /* Acquire a reference to the MocCtx.
   */
  status = AcquireMocCtxRef (pMocCtx);
  if (OK != status)
    goto exit;

  flag = 1;

  /* Now call the Operator passed in to complete the process.
   */
  status = KeyOperator (
    (MocAsymKey)pKey, pMocCtx, keyOp, pOperatorInfo, NULL, NULL);
  if (OK != status)
    goto exit;

  pKey->pMocCtx = pMocCtx;
  flag = 0;
  *ppNewKey = pKey;
  pKey = NULL;

exit:

  if (NULL != pKey)
  {
    CRYPTO_freeMocAsymKey (&pKey, NULL);
  }
  if (0 != flag)
  {
    ReleaseMocCtxRef (pMocCtx);
  }

  return (status);
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_freeMocAsymKey (
  MocAsymKey *ppMocAsymKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status, fStatus;
  MocCtx pMocCtx = NULL;

  /* Anything to free?
   */
  status = OK;
  if (NULL == ppMocAsymKey)
    goto exit;

  if (NULL == *ppMocAsymKey)
    goto exit;

  pMocCtx = (*ppMocAsymKey)->pMocCtx;
  if (NULL != (*ppMocAsymKey)->KeyOperator)
  {
    fStatus = (*ppMocAsymKey)->KeyOperator (
      *ppMocAsymKey, pMocCtx, MOC_ASYM_OP_FREE, NULL, NULL, ppVlongQueue);
    if (OK == status)
      status = fStatus;
  }

  fStatus = DIGI_MEMSET ((void *)(*ppMocAsymKey), 0, sizeof (MocAsymmetricKey));
  if (OK == status)
    status = fStatus;

  fStatus = DIGI_FREE ((void **)ppMocAsymKey);
  if (OK == status)
    status = fStatus;

exit:

  if ( (OK == status) && (NULL != pMocCtx) )
  {
    ReleaseMocCtxRef (pMocCtx);
  }

  return (status);
}


/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getSecuritySize (
  MocAsymKey pKey,
  ubyte4 *pSecuritySize
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pSecuritySize) )
    goto exit;

  if (NULL != pKey->KeyOperator)
  {
    status = pKey->KeyOperator (
      pKey, pKey->pMocCtx, MOC_ASYM_OP_GET_SECURITY_SIZE, NULL,
      (void *)pSecuritySize, NULL);
  }

exit:

  return (status);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getDomainParam (
  MocAsymKey pKey,
  ubyte4 param,
  ubyte4 *pParamValue
  )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey || NULL == pParamValue)
        goto exit;

    if (NULL != pKey->KeyOperator)
    {
        status = pKey->KeyOperator (pKey, pKey->pMocCtx, MOC_ASYM_OP_GET_PARAMS, (void *) &param,
                                    (void *) pParamValue, NULL);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getLocalKeyReference (
  MocAsymKey pKey,
  void **ppLocalKey
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == ppLocalKey) )
    goto exit;

  if (NULL != pKey->KeyOperator)
  {
    status = pKey->KeyOperator (
      pKey, pKey->pMocCtx, MOC_ASYM_OP_GET_LOCAL_KEY, NULL,
      (void *)ppLocalKey, NULL);
  }

exit:

  return (status);
}


/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_cloneMocAsymKey (
  MocAsymKey pKeyToClone,
  MocAsymKey *ppClonedKey,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocAsymKey pCloneKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyToClone) || (NULL == ppClonedKey) )
    goto exit;

  status = ERR_INVALID_INPUT;
  if (NULL == pKeyToClone->KeyOperator)
    goto exit;

  status = pKeyToClone->KeyOperator (
    pKeyToClone, pKeyToClone->pMocCtx, MOC_ASYM_OP_CLONE, NULL,
    (void *)&pCloneKey, ppVlongQueue);
  if (OK != status)
    goto exit;

  *ppClonedKey = pCloneKey;
  pCloneKey = NULL;

exit:

  if (NULL != pCloneKey)
  {
    CRYPTO_freeMocAsymKey (&pCloneKey, NULL);
  }

  return status;
}


/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_validatePubPriMatch (
  MocAsymKey pPriKey,
  MocAsymKey pPubKey,
  byteBoolean *pMatch
  )
{
  MSTATUS status;

  /* Validate pointers are not NULL */
  status = ERR_NULL_POINTER;
  if ( (NULL == pPriKey) || (NULL == pPubKey) || (NULL == pMatch) )
    goto exit;

  if (NULL != pPriKey->KeyOperator)
  {
    status = pPriKey->KeyOperator(
      pPriKey, pPriKey->pMocCtx, MOC_ASYM_OP_VALIDATE_PUB_PRI_MATCH,
      (void *)pPubKey, (void *)pMatch, NULL);
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getPubFromPri (
  MocAsymKey pPriKey,
  MocAsymKey *ppPubKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocAsymKey pNewPub = NULL;

  /* Validate pointers are not NULL */
  status = ERR_NULL_POINTER;
  if ((NULL == pPriKey) || (NULL == ppPubKey))
    goto exit;

  /* If the key object is not private, error.
   */
  status = ERR_KEY_IS_NOT_PRIVATE;
  if (0 == (MOC_LOCAL_TYPE_PRI & pPriKey->localType))
    goto exit;

  if (NULL != pPriKey->KeyOperator)
  {
    status = pPriKey->KeyOperator (
      pPriKey, pPriKey->pMocCtx, MOC_ASYM_OP_PUB_FROM_PRI,
      NULL, (void *)&pNewPub, ppVlongQueue);
    if (OK != status)
      goto exit;
  }

  *ppPubKey = pNewPub;
  pNewPub = NULL;

exit:
  if (NULL != pNewPub)
  {
    CRYPTO_freeMocAsymKey (&pNewPub, ppVlongQueue);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_validateKey (
  MocAsymKey pKey,
  byteBoolean *pIsValid
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pIsValid) || (NULL == pKey->KeyOperator) )
    goto exit;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_VALIDATE_KEY, NULL, (void *)pIsValid, NULL);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_updateAsymOperatorData (
  MocAsymKey pKey,
  void *pOperatorData
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pOperatorData) || (NULL == pKey->KeyOperator) )
    goto exit;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_UPDATE_OP_DATA, pOperatorData, NULL, NULL);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getAsymOperatorAndInfoFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  MKeyOperator *ppKeyOperator,
  void **ppOperatorInfo
  )
{
  MSTATUS status;
  ubyte4 listCount;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyOperatorAndInfo *pKeyOperators = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pMocCtx) || (NULL == ppKeyOperator) )
    goto exit;

  /* We need the list of Operators */
  status = MocAcquireSubCtxRef (
    pMocCtx, MOC_SUB_CTX_TYPE_OP_LIST, &pSubCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pSubCtx->pLocalCtx);
  pKeyOperators = pOpList->pKeyOperators;
  listCount = pOpList->keyOperatorCount;

  status = ERR_INVALID_ARG;
  if (listCount <= index)
    goto exit;

  /* We already know the index, simply set the pointers */
  *ppKeyOperator = pKeyOperators[index].KeyOperator;

  /* If the caller wanted the associated info give that back as well */
  if (NULL != ppOperatorInfo)
  {
    *ppOperatorInfo = pKeyOperators[index].pOperatorInfo;
  }

  status = OK;

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getAsymObjectFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  void *pOperatorInfo,
  ubyte4 keyType,
  MocAsymKey *ppObj
  )
{
  MSTATUS status;
  MKeyOperator KeyOperator;
  void *pOpInfo = NULL;
  MocAsymKey pNewKey = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == ppObj)
    goto exit;

  *ppObj = NULL;

  /* Get the operator and info from the MocCtx based on the index */
  status = CRYPTO_getAsymOperatorAndInfoFromIndex (
    index, pMocCtx, &KeyOperator, &pOpInfo);
  if (OK != status)
    goto exit;

  /* If the caller specified an operator info then use it, disregarding
   * the operator info from the list */
  if (NULL != pOperatorInfo)
  {
    pOpInfo = pOperatorInfo;
  }

  /* Create the object with the specified key type */
  status = CRYPTO_createMocAsymKey (
    KeyOperator, pOpInfo, pMocCtx, keyType, &pNewKey);
  if (OK != status)
    goto exit;

  *ppObj = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pNewKey)
  {
    CRYPTO_freeMocAsymKey(&pNewKey, NULL);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getKeyDataAlloc (
  MocAsymKey pKey,
  void *pOperatorData,
  ubyte keyType
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pOperatorData) || (NULL == pKey->KeyOperator) )
    goto exit;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_GET_KEY_DATA, (void *)&keyType,
    pOperatorData, NULL);

exit:

  return status;
}


/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_freeKeyTemplate (
  MocAsymKey pKey,
  void *pOperatorData
  )
{
  MSTATUS status = OK;

  if (NULL == pOperatorData)
    goto exit;

  status = ERR_NULL_POINTER;
  if (NULL == pKey)
    goto exit;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_FREE_KEY_TEMPLATE, pOperatorData, NULL,
    NULL);

exit:

  return status;
}


/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_setKeyData (
  MocAsymKey pKey,
  void *pOperatorData
  )
{
  MSTATUS status;
  ubyte4 algoFlag = 0;
  MRsaKeyTemplate *pTemplate = NULL;
  ubyte *pModulus = NULL;
  ubyte4 modulusLen = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pOperatorData) || (NULL == pKey->KeyOperator) )
    goto exit;

  algoFlag = (pKey->localType & MOC_LOCAL_TYPE_COM_MASK) |
             (pKey->localType & MOC_LOCAL_TYPE_ALG_MASK);

  /* If this is a software RSA Key, ensure the modulus length is supported */
  if ( (0 != (MOC_LOCAL_TYPE_SW & pKey->localType)) && (MOC_ASYM_ALG_RSA == algoFlag) )
  {
    pTemplate = (MRsaKeyTemplate *)pOperatorData;

    /* Is there a modulus value being set on this call? */
    if ( (NULL != pTemplate->pN) && (0 != pTemplate->nLen) )
    {
      /* Trim any leading zero bytes from the modulus, this accounts for any
       * prepended zero bytes added during ASN1 encoding */
      pModulus = pTemplate->pN;
      modulusLen = pTemplate->nLen;

      while ( (1 < modulusLen) && (0 == *pModulus) )
      {
        pModulus++;
        modulusLen--;
      }

      status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
      if ( !(0x80 & *pModulus) || ( (128 != modulusLen) && (256 != modulusLen) &&
             (384 != modulusLen) && (512 != modulusLen) ) )
      {
        goto exit;
      }
    }
  }

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_SET_KEY_DATA, pOperatorData, NULL, NULL);

exit:

  return status;
}


/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_getAsymAlgId (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 bufferSize,
  ubyte4 *pAlgIdLen
  )
{
  MSTATUS status;
  MKeyOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pAlgIdLen) )
    goto exit;

  status = ERR_INVALID_ARG;
  if (NULL == pKey->KeyOperator)
    goto exit;

  outputInfo.pBuffer = pAlgId;
  outputInfo.bufferSize = bufferSize;
  outputInfo.pLength = pAlgIdLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_GET_LATEST_ALG_ID, NULL,
    (void *)&outputInfo, NULL);

exit:

  return (status);
}


/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_serializeMocAsymKeyAlloc (
  MocAsymKey pKeyToSerialize,
  serializedKeyFormat format,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status;
  MSerializeInfo serialInfo = {
    .ppSerializedKey = ppSerializedKey,
    .pSerializedKeyLen = pSerializedKeyLen,
    .derLen = 0, .headerLen = 0, .footerLen = 0,
    .formatToUse = format,
    .pDerEncoding = NULL, .pHeader = NULL, .pFooter = NULL,
    .pPubHeader = MOC_PUB_PEM_HEADER,
    .pPubFooter = MOC_PUB_PEM_FOOTER,
    .pPriHeader = MOC_PRI_PEM_HEADER,
    .pPriFooter = MOC_PRI_PEM_FOOTER,
    .dataToReturn = {0}
  };

  status = ERR_NULL_POINTER;
  if (NULL == pKeyToSerialize)
    goto exit;

  /* Ensure there is a valid operator */
  status = ERR_INVALID_INPUT;
  if (NULL == pKeyToSerialize->KeyOperator)
    goto exit;

  /* Execute initialization code common to all serialization routines */
  status = SerializeCommonInit(&serialInfo, format);
  if (OK != status)
    goto exit;

  /* Have the key serialize itself */
  status = pKeyToSerialize->KeyOperator (
    pKeyToSerialize, pKeyToSerialize->pMocCtx, MOC_ASYM_OP_SERIALIZE,
    &(serialInfo.formatToUse), (void *)&(serialInfo.dataToReturn), NULL);
  if (OK != status)
    goto exit;

  /* We now have the encoding, if the requested format is not PEM we are done */
  if (serialInfo.formatToUse == format)
    goto exit;

  /* Wrap encoding into PEM format, common to all serialization routines */
  status = SerializeCommon(&serialInfo);

exit:

  if (NULL != serialInfo.pDerEncoding)
  {
    DIGI_FREE ((void **)&(serialInfo.pDerEncoding));
  }

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_deserializeMocAsymKey (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MocCtx pMocCtx,
  MocAsymKey *ppDeserializedKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 index, keyDerLen, pemType;
  MocCtx pMocCtxToUse = NULL;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  ubyte *pKeyDer = NULL;
  MocAsymKey pNewKey = NULL;
  MKeyOperatorData keyData;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSerializedKey) || (NULL == ppDeserializedKey) )
    goto exit;

  pMocCtxToUse = pMocCtx;

  /* If the caller passed a NULL MocCtx and the crypto interface is enabled,
   * try to get the MocCtx for TAP created by the crypto interface core during
   * initialization. */
  if (NULL == pMocCtxToUse)
  {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)

    status = CRYPTO_INTERFACE_getTapMocCtx(&pMocCtxToUse);
    if (OK != status)
      goto exit;

#else

    status = ERR_NULL_POINTER;
    goto exit;

#endif
  }

  /* Check the first byte of the serialized key. If it is '-', it is PEM. If it
   * is 00, it is a key blob. If it is 0x30, it is the DER encoding.
   */
  keyData.pData = pSerializedKey;
  keyData.length = serializedKeyLen;
  if ('-' == pSerializedKey[0])
  {
    /* If this is PEM, call the function that decodes these types of structures.
     */
    status = BASE64_decodePemMessageAlloc (
      pSerializedKey, serializedKeyLen, &pemType, &pKeyDer, &keyDerLen);
    if (OK != status)
      goto exit;

    keyData.pData = pKeyDer;
    keyData.length = keyDerLen;
  }

  status = MocAcquireSubCtxRef (
    pMocCtxToUse, MOC_SUB_CTX_TYPE_OP_LIST, &pSubCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pSubCtx->pLocalCtx);

  for (index = 0; index < pOpList->keyOperatorCount; ++index)
  {
    /* Build a MocAsymKey for the given Operator.
     */
    status = CRYPTO_createMocAsymKey (
      pOpList->pKeyOperators[index].KeyOperator,
      pOpList->pKeyOperators[index].pOperatorInfo, pMocCtxToUse, 0, &pNewKey);
    if (OK != status)
      goto exit;

    /* Call on the Operator. If it works, we're done.
     */
    status = pNewKey->KeyOperator (
      pNewKey, pMocCtxToUse, MOC_ASYM_OP_DESERIALIZE, (void *)&keyData,
      NULL, ppVlongQueue);
    if (OK == status)
      break;

    CRYPTO_freeMocAsymKey (&pNewKey, ppVlongQueue);
  }

  /* If we broke out early we found a match. Otherwise, error.
   */
  status = ERR_INVALID_INPUT;
  if (index >= pOpList->keyOperatorCount)
    goto exit;

  status = OK;

  *ppDeserializedKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }
  if (NULL != pNewKey)
  {
    CRYPTO_freeMocAsymKey (&pNewKey, ppVlongQueue);
  }
  if (NULL != pKeyDer)
  {
    DIGI_FREE ((void **)&pKeyDer);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SERIALIZE__)) */

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
