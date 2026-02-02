/*
 * keyf.c
 *
 * Key Functions
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
@file       keyf.c
@brief      Key Functions
@details    Add details here.

@filedoc    keyf.c
*/
#include "../cap/capsym.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

static MSTATUS CRYPTO_validateSymAlgoSupport (
  MSymOperator SymOperator,
  ubyte4 keyLen
  )
{
  MSTATUS status;
  ubyte4 localType = 0;
  ubyte4 algoFlag = 0;

  /* Get the local type from the provided MocSymCtx */
  status = SymOperator (
    NULL, NULL, MOC_SYM_OP_GET_LOCAL_TYPE, NULL, (void *)&localType);
  if (OK != status)
    goto exit;

  /* If this is a software implementation, ensure we support the algorithm */
  if (0 != (MOC_LOCAL_TYPE_SW & localType))
  {
    /* Mask off bits to get the algorithm this operator claims to be implementing */
    algoFlag = (localType & MOC_LOCAL_TYPE_COM_MASK) |
               (localType & MOC_LOCAL_TYPE_ALG_MASK);

    /* Do we support this algorithm? If so is this a valid key length
    * for that algorithm? */
    status = ERR_INVALID_INPUT;
    switch(algoFlag)
    {
      case MOC_SYM_ALG_AES:
      case MOC_SYM_ALG_AES_ECB:
      case MOC_SYM_ALG_AES_CBC:
      case MOC_SYM_ALG_AES_CFB:
      case MOC_SYM_ALG_AES_OFB:
      case MOC_SYM_ALG_AES_CTR:
      case MOC_SYM_ALG_AES_GCM:
      case MOC_SYM_ALG_AES_CCM:
      case MOC_SYM_ALG_AES_EAX:
      case MOC_SYM_ALG_AES_CMAC:
        if ( (16 != keyLen) && (24 != keyLen) && (32 != keyLen) )
        {
          status = ERR_AES_BAD_KEY_LENGTH;
          goto exit;
        }
        break;

      case MOC_SYM_ALG_AES_XTS:
        if ( (32 != keyLen) && (64 != keyLen) )
        {
            status = ERR_AES_BAD_KEY_LENGTH;
            goto exit;
        }
        break;

      case MOC_SYM_ALG_DES:
      case MOC_SYM_ALG_DES_ECB:
      case MOC_SYM_ALG_DES_CBC:
        if (8 != keyLen)
        {
          status = ERR_DES_BAD_KEY_LENGTH;
          goto exit;
        }
        break;

      case MOC_SYM_ALG_TDES:
      case MOC_SYM_ALG_TDES_ECB:
      case MOC_SYM_ALG_TDES_CBC:
        if (24 != keyLen)
        {
          status = ERR_3DES_BAD_KEY_LENGTH;
          goto exit;
        }
        break;

      case MOC_SYM_ALG_ARC2_CBC:
        if ( (1 > keyLen) || (128 < keyLen) )
        {
          status = ERR_ARC2_BAD_KEY_LENGTH;
          goto exit;
        }
        break;

      case MOC_SYM_ALG_ARC4:
        if ( (5 > keyLen) || (256 < keyLen) )
        {
          status = ERR_ARC4_BAD_KEY_LENGTH;
          goto exit;
        }
        break;

      case MOC_SYM_ALG_RC5:
      case MOC_SYM_ALG_RC5_CBC:
      case MOC_SYM_ALG_RC5_ECB:
        if ( (5 > keyLen) || (255 < keyLen) )
        {
          status = ERR_RC5_INVALID_KEY_LEN;
          goto exit;
        }
        break;

      case MOC_SYM_ALG_POLY1305:
      case MOC_SYM_ALG_CHACHAPOLY:
        if (32 != keyLen)
        {
          status = ERR_CRYPTO_BAD_KEY_LENGTH;
          goto exit;
        }

      case MOC_SYM_ALG_HMAC:
        break;

      case MOC_SYM_ALG_CHACHA20:
        if (32 != keyLen)
        {
          status = ERR_CHACHA20_BAD_KEY_LENGTH;
          goto exit;
        }
        break;

      case MOC_SYM_ALG_BLOWFISH_CBC:
        if (4 > keyLen || 56 < keyLen)
        {
          status = ERR_BLOWFISH_BAD_KEY_LENGTH;
          goto exit;
        }
        break;

      default:
        goto exit;
    }
  }

  status = OK;

exit:
  return status;
}

extern MSTATUS CRYPTO_generateSymKeyEx (
  MSymOperator SymOperator,
  MocCtx pMocCtx,
  MocSymCtx *ppNewSymCtx,
  ubyte4 keySizeBits,
  void *pKeyGenArgs
  )
{
  MSTATUS status;
  MSymKeyGenInfoEx inputInfo;
  MSymKeyGenResult outputInfo;
  MocSymCtx pNewCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == SymOperator) || (NULL == ppNewSymCtx) )
    goto exit;

  status = CRYPTO_validateSymAlgoSupport(SymOperator, keySizeBits/8);
  if (OK != status)
    goto exit;

  inputInfo.keySizeBits = keySizeBits;
  inputInfo.pOperatorInfo = pKeyGenArgs;
  outputInfo.ppNewSymCtx = &pNewCtx;

  status = SymOperator (
    NULL, pMocCtx, MOC_SYM_OP_GENERATE_KEY_EX, (void *)&inputInfo,
    (void *)&outputInfo);

  *ppNewSymCtx = pNewCtx;
  pNewCtx = NULL;

exit:
  return status;
}

extern MSTATUS CRYPTO_generateSymKey (
  MocSymCtx pSymCtx,
  RNGFun RngFun,
  void *pRngArg,
  ubyte4 keySizeBits,
  ubyte *pKeyBuf,
  ubyte4 bufferSize,
  ubyte4 *pKeyLen
  )
{
  MSTATUS status;
  MSymKeyGenInfo inputInfo;
  MSymOperatorBuffer outputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pSymCtx->SymOperator) )
    goto exit;

  status = CRYPTO_validateSymAlgoSupport(pSymCtx->SymOperator, keySizeBits/8);
  if (OK != status)
    goto exit;

  randInfo.RngFun = RngFun;
  randInfo.pRngFunArg = pRngArg;
  inputInfo.pRandInfo = &randInfo;
  inputInfo.keySizeBits = keySizeBits;
  outputInfo.pBuffer = pKeyBuf;
  outputInfo.bufferSize = bufferSize;
  outputInfo.pOutputLen = pKeyLen;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_GENERATE_KEY, (void *)&inputInfo,
    (void *)&outputInfo);

exit:

  return (status);
}

extern MSTATUS CRYPTO_loadSymKey (
  MocSymCtx pSymCtx,
  ubyte *pKeyBuf,
  ubyte4 keyLenBytes
  )
{
  MSTATUS status;
  MSymOperatorData inputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pKeyBuf) || (0 == keyLenBytes) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = CRYPTO_validateSymAlgoSupport(pSymCtx->SymOperator, keyLenBytes);
  if (OK != status)
    goto exit;

  inputInfo.pData = pKeyBuf;
  inputInfo.length = keyLenBytes;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_LOAD_KEY, (void *)&inputInfo, NULL);

exit:

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
