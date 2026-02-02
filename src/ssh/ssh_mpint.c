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

#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || !defined(__DISABLE_DIGICERT_KEY_GENERATION__)

MOC_EXTERN MSTATUS SSH_mpintByteStringFromByteString (
  const ubyte* pValue,
  ubyte4 valueLen,
  ubyte sign,
  ubyte** ppDest,
  sbyte4* pRetLen
  )
{
  ubyte4 extraByte = 0;
  ubyte *pDest = NULL; /* buffer used to store output */
  ubyte4 destLen = 0;
  MSTATUS status = OK;

  if ((NULL == pValue) || (NULL == ppDest) || (NULL == pRetLen))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppDest = NULL;
  *pRetLen = 0;

  /* ignore any zero bytes at the beginning of pValue, ok to move passed by value ptr */
  while (valueLen > 0 && 0x00 == pValue[0])
  {
    pValue++;
    valueLen--;
  }

  if (valueLen > 0)
  {
    /* for positive integers, if first bit is set we'll need to pad with an extra 0x00 byte */
    if (0 == sign && (pValue[0] & 0x80) )
    {
      extraByte = 1;
    }
    /* for negative integers we need to pad with an extra byte if the value is greater than 0x8000.... to the proper length  */
    else if (0 != sign)
    {
      if (pValue[0] > 0x80)
      {
        extraByte = 1;
      }
      else if (pValue[0] == 0x80)
      {
        ubyte *pTemp = (ubyte *) pValue + 1;
        ubyte4 tempLen = valueLen - 1;

        /* check if all bytes after the 0x80 are 0x00 */
        while (tempLen > 0 && 0x00 == pTemp[0])
        {
          pTemp++;
          tempLen--;
        }
        if (tempLen)
        {
          extraByte = 1;
        }
      }
    }
  }

  /* 4 byte length plus potential extra byte plus raw value length */
  destLen = 4 + extraByte + valueLen;

  status = DIGI_MALLOC((void **) &pDest, destLen);
  if (OK != status)
      goto exit;

  /* length */
  BIGEND32(pDest, extraByte + valueLen);

  /* extra byte */
  if (1 == extraByte)
  {
    pDest[4] = (sign) ? 0xFF : 0x00;
  }

  if (valueLen > 0)
  {
    /* raw value*/
    (void) DIGI_MEMCPY(pDest + 4 + extraByte, pValue, valueLen);

    /* convert to 2s complement if negative */
    if (sign)
    {
      ubyte4 i;

      /* flip all the bytes */      
      for (i = 4 + extraByte; i < destLen; ++i)
      {
        pDest[i] ^= 0xFF;
      }

      /* add 1, start at the end */
      for (i = destLen - 1; i >= 4 + extraByte; --i)
      {
        pDest[i]++;
        if (pDest[i])
           break;
      }
      /* ignore any overflow carry */
    }
  }

  *ppDest = pDest; pDest = NULL;
  *pRetLen = (sbyte4) destLen;

exit:

  /* no goto exit after DIGI_MALLOC, no cleanup needed */
  return status;
}
#endif /* defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || !defined(__DISABLE_DIGICERT_KEY_GENERATION__) */

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
    status = DIGI_MALLOC((void**)&pTmpArray, length);
    if(OK != status)
        goto exit;

    /* copy value of mpint array into temporary buffer */
    status = DIGI_MEMCPY(pTmpArray, pArray, length);
    if(OK != status)
        goto exit;
  }
  
  *ppNewArray = pTmpArray;
  pTmpArray = NULL;

exit:
  DIGI_FREE((void**)&pTmpArray);
  return status;

}
