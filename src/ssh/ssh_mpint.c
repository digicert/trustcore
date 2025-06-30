/**
 * @file  ssh_mpint.c
 * @brief mpint byte array conversions
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

/*----------------------------------------------------------------------------*/
#include "../ssh/ssh_mpint.h"

#if defined(__ENABLE_MOCANA_PEM_CONVERSION__) || !defined(__DISABLE_MOCANA_KEY_GENERATION__)

MOC_EXTERN MSTATUS SSH_mpintByteStringFromByteString (
  const ubyte* pValue,
  ubyte4 valueLen,
  ubyte sign,
  ubyte** ppDest,
  sbyte4* pRetLen
  )
{
  ubyte4 length = valueLen;
  ubyte4 leadingByte = 0; /* 1 if we need a lead zero or 0xFF byte, 0 otherwise */
  ubyte *pDest = NULL; /* buffer used to store output */
  ubyte4 bitLen = 0;
  MSTATUS status = OK;
  ubyte4 lastWord = 0; /* here we store the value of the last 4 bytes */ 

  if ((NULL == pValue) || (NULL == ppDest) || (NULL == pRetLen))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppDest = NULL;
  *pRetLen = 0;

  /* get size of buffer in bits, if len is a multiple of 8, we need a 00 byte of ff
   * otherwise we can ignore*/

  /* convert the last 4 bytes of buffer into a ubyte4  */
  if(0 < valueLen)
  {
    if (valueLen >= 4)
    {
      lastWord = (lastWord | pValue[0]);
      lastWord = (lastWord << 8);
      lastWord = (lastWord | pValue[1]);
      lastWord = (lastWord << 8);
      lastWord = (lastWord | pValue[2]);
      lastWord = (lastWord << 8);
      lastWord = (lastWord | pValue[3]);
    } else if (valueLen >= 3)
    {
      lastWord = (lastWord | pValue[0]);
      lastWord = (lastWord << 8);
      lastWord = (lastWord | pValue[1]);
      lastWord = (lastWord << 8);
      lastWord = (lastWord | pValue[2]);

    } else if (valueLen >= 2)
    {
      lastWord = (lastWord | pValue[0]);
      lastWord = (lastWord << 8);
      lastWord = (lastWord | pValue[1]);

    } else if (valueLen >= 1)
    {
      lastWord = (lastWord | pValue[0]);
    }

    bitLen = MOC_BITLENGTH(lastWord);
    leadingByte = (0 == bitLen % 8) ? 1 : 0;
  }

  /* get length of buffer */
  pDest = (ubyte *)MALLOC(length + 4 + leadingByte);
  if (!pDest)
  {
    status = ERR_MEM_ALLOC_FAIL;
    goto exit;
  }

  /* length */
  BIGEND32(pDest, length + leadingByte);

  if (1 == leadingByte)
  {
    pDest[4] = (sign) ? 0xFF : 0x00;
  }

  /* copy buffer into output buffer */
  status = MOC_MEMCPY(pDest + 4 + leadingByte, pValue, valueLen);
  if (OK != status)
      goto exit;

  *pRetLen = length + 4 + leadingByte;

  /* convert to 2 complement if negative */
  if (sign)
  {
    ubyte4 i;
    /* flip all the bytes */
    for (i = 4 + leadingByte; i < (ubyte4)*pRetLen; ++i)
    {
      pDest[i] ^= 0xFF;
    }
    /* add 1 */
    for (i = *pRetLen - 1; i >= 4 + leadingByte; --i)
    {
      if (0xFF == pDest[i])
      {
        pDest[i] = 0;
      }
      else
      {
        pDest[i]++;
        break;
      }
    }
  }

  *ppDest = pDest;
  pDest = NULL;
exit:
  return status;
}

#endif /* defined(__ENABLE_MOCANA_PEM_CONVERSION__) || !defined(__DISABLE_MOCANA_KEY_GENERATION__) */

/*----------------------------------------------------------------------------*/

/* This function converts an ssh string, whether it is an mpint or not, into a byte buffer. It does not handle padding
   in case of an mpint.  */
MOC_EXTERN MSTATUS SSH_getByteStringFromMpintBytes(
  const ubyte *pArray, 
  ubyte4 bytesAvailable,
  ubyte **ppNewArray,  
  ubyte4 *pRetNumBytesUsed
  )
{
  sbyte4 length = 0;
  ubyte *pTmpArray = NULL;
  MSTATUS status = OK;

  if ((NULL == pArray) || (NULL == ppNewArray) || (NULL == pRetNumBytesUsed))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppNewArray = NULL;

  /* nothing to copy */
  if (4 > bytesAvailable)
  {
    status = ERR_BAD_LENGTH;
    goto exit;
  }
  /* calc mpint length */
  length = ((sbyte4)(pArray[3]));
  length |= ((sbyte4)(pArray[2])) << 8;
  length |= ((sbyte4)(pArray[1])) << 16;
  length |= ((sbyte4)(pArray[0])) << 24;

  *pRetNumBytesUsed = length;

  if (((((sbyte4)bytesAvailable) - 4) < length) || (0 > length))
  {
    status = ERR_BAD_LENGTH;
    goto exit;
  }

  if (length > 0)
  {
    pArray += 4;

    /* allocate temporary buffer */
    status = MOC_MALLOC((void**)&pTmpArray, length);
    if(OK != status)
        goto exit;

    /* copy value of mpint array into temporary buffer */
    status = MOC_MEMCPY(pTmpArray, pArray, length);
    if(OK != status)
        goto exit;
  }
  
  *ppNewArray = pTmpArray;
  pTmpArray = NULL;

exit:
  MOC_FREE((void**)pTmpArray);
  return status;

}
