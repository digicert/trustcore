/**
 * @file  vlong_conv.c
 * @brief Very Long Integer Conversion Function Implementations
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#if defined(__RTOS_THREADX__) && !defined(__RTOS_AZURE__)
#include "common/vlong.h"
#else
#include "../../common/vlong.h"
#endif

/*----------------------------------------------------------------------------*/

static ubyte getByte (
  const vlong *pThis, 
  ubyte4 byteIndex
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_makeVlongFromUnsignedValue (
  vlong_unit value, 
  vlong **ppRetVlong, 
  vlong **ppVlongQueue
  )
{
  vlong *pTemp = NULL;
  MSTATUS status;

  if (NULL == ppRetVlong)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if (OK > (status = VLONG_allocVlong(&pTemp, ppVlongQueue)))
    goto exit;

  DEBUG_RELABEL_MEMORY(*ppRetVlong);

  if (OK > (status = assignUnsignedToVlong(pTemp, value)))
    goto exit;

  *ppRetVlong = pTemp;
  pTemp = NULL;

exit:
  VLONG_freeVlong(&pTemp, ppVlongQueue);

  return status;

} /* VLONG_makeVlongFromUnsignedValue */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_makeVlongFromVlong (
  const vlong* pValue, 
  vlong **ppRetVlong, 
  vlong **ppVlongQueue
  )
{
  MSTATUS status;

  /* VLONG_allocVlong() doesn't allow ppRetVlong to be NULL */
  if (NULL == ppRetVlong)
    return ERR_NULL_POINTER;

  if (OK <= (status = VLONG_allocVlong(ppRetVlong, ppVlongQueue)))
  {
    DEBUG_RELABEL_MEMORY(*ppRetVlong);

    if (OK > (status = VLONG_copySignedValue(*ppRetVlong, pValue)))
      VLONG_freeVlong(ppRetVlong, ppVlongQueue);
  }

  return status;

} /* VLONG_makeVlongFromVlong */

/*----------------------------------------------------------------------------*/

/* ff additional function to converts from bytes string */
/* byte string is completely in big endian format */
/* but the internal representation used array of unsigned so */
/* convert each x bytes to the correct unsigned vlong_unit */
MOC_EXTERN MSTATUS VLONG_vlongFromByteString (
  const ubyte* byteString, 
  sbyte4 len,
  vlong **ppRetVlong, 
  vlong **ppVlongQueue
  )
{
  sbyte4 i, j, count;
  vlong_unit elem;
  MSTATUS status;

  if (NULL == ppRetVlong)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if (0 > len)
  {
    status = ERR_BAD_LENGTH;
    goto exit;
  }

  if (OK > (status = VLONG_allocVlong(ppRetVlong, ppVlongQueue)))
    goto exit;

  DEBUG_RELABEL_MEMORY(*ppRetVlong);

  if (OK > (status = VLONG_reallocVlong(*ppRetVlong, 1 + (len / sizeof(vlong_unit)))))
    goto exit;

  /* now copy the contents of the byte string to the array of vlong_units */
  /* respecting the endianess of the architecture */

  count = 0;

  for (i = len - 1; i >= 0; ++count)
  {
    elem = 0;

    for (j = 0; j < (sbyte4)(sizeof(vlong_unit)) && i >= 0; ++j, --i)
    {
      elem |= (((vlong_unit)byteString[i]) << (j * 8));
    }

    if (OK > (status = VLONG_setVlongUnit(*ppRetVlong, count, elem)))
      goto exit;
  }

exit:
  return status;

} /* VLONG_vlongFromByteString */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_vlongFromUByte4String (
  const ubyte4 *pU4Str, 
  ubyte4 len, 
  vlong **ppNewVlong
  )
{
  MSTATUS status;
  ubyte4 index;

  if ((NULL == pU4Str) || (NULL == ppNewVlong))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppNewVlong = NULL;

  if (OK > (status = VLONG_allocVlong(ppNewVlong, NULL)))
    goto exit;

  if (NULL != ppNewVlong)
  {
    DEBUG_RELABEL_MEMORY(*ppNewVlong);
  }
  
  if (0 == len)
    goto exit;

#ifdef __ENABLE_DIGICERT_64_BIT__

  if (OK > (status = VLONG_reallocVlong(*ppNewVlong, ((len + 1) >> 1))))
    goto cleanup;

  index = 0;
  while ((1 < len) && (OK <= status))
  {
    vlong_unit u = ((vlong_unit) pU4Str[len - 2]);
    u <<= 32;
    u |= ((vlong_unit) pU4Str[len - 1]);

    status = VLONG_setVlongUnit(*ppNewVlong, index, u);
    index++;
    len -= 2;
  }
  if (OK <= status && 1 == len)
  {
    status = VLONG_setVlongUnit(*ppNewVlong, index, pU4Str[0]);
  }

#else
  if (OK > (status = VLONG_reallocVlong(*ppNewVlong, len)))
    goto cleanup;

  index = 0;
  while ((0 < len) && (OK <= status))
  {
    status = VLONG_setVlongUnit(*ppNewVlong, index, pU4Str[--len]);
    index++;
  }
#endif

cleanup:
  if (OK > status)
    VLONG_freeVlong(ppNewVlong, NULL);

exit:
  return status;

} /* VLONG_vlongFromUByte4String */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_byteStringFromVlong (
  const vlong* pValue, 
  ubyte* pDest, 
  sbyte4* pRetLen
  )
{
  sbyte4 requiredLen;
  sbyte4 index;
  vlong_unit elem;
  MSTATUS status = OK;

  if (NULL == pValue)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  /* return a value precise to the byte */
  requiredLen = (sbyte4)((7 + VLONG_bitLength(pValue)) / 8);

  if (pDest)
  {
    if (*pRetLen >= requiredLen)
    {
      /* convert from array of vlong_unit to arrays of bytes */
      /* this just requires converting the unsigned to big endian format */
      ubyte4 mode = requiredLen & (sizeof(vlong_unit) - 1);

      /* pad with 0 if necessary instead of setting *pRetLen to requiredLen
                This is because some higher levels API (rsa.h) do not provide
                a way to return the length of the result. They assume that
                length output = length input which is true in most cases */
      while (*pRetLen > requiredLen)
      {
        *pDest++ = 0;
        requiredLen++;
      }
      if (pValue->numUnitsUsed > 0)
      {
        elem = VLONG_getVlongUnit(pValue, pValue->numUnitsUsed - 1);
        if (0 == mode)
        {
          mode = sizeof(vlong_unit);
        }
        switch (mode)
        {
/* next #ifdef is to prevent warnings (and reduce code size) -- numerically impossible */
#ifdef __ENABLE_DIGICERT_64_BIT__
        case 8:
          *pDest++ = (ubyte)((elem >> 56) & 0xff);
        case 7:
          *pDest++ = (ubyte)((elem >> 48) & 0xff);
        case 6:
          *pDest++ = (ubyte)((elem >> 40) & 0xff);
        case 5:
          *pDest++ = (ubyte)((elem >> 32) & 0xff);
#endif
        case 4:
          *pDest++ = (ubyte)((elem >> 24) & 0xff);
        case 3:
          *pDest++ = (ubyte)((elem >> 16) & 0xff);
        case 2:
          *pDest++ = (ubyte)((elem >> 8) & 0xff);
        case 1:
          *pDest++ = (ubyte)elem;
        }
      }

      for (index = pValue->numUnitsUsed - 2; 0 <= index; --index)
      {
        sbyte4 i;

        elem = VLONG_getVlongUnit(pValue, index);

        for (i = sizeof(vlong_unit) - 1; i >= 0; --i)
        {
          *pDest++ = (ubyte)((elem >> (i * 8)) & 0xFF);
        }
      }
    }
    else
    {
      status = ERR_BUFFER_OVERFLOW;
    }
  }
  else
  {
    *pRetLen = requiredLen;
  }

exit:
  return status;

} /* VLONG_byteStringFromVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_fixedByteStringFromVlong (
  vlong* pValue, 
  ubyte* pDest, 
  sbyte4 fixedLength
  )
{
  MSTATUS status = OK;

  if ((NULL == pValue) || (NULL == pDest))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  while (0 < fixedLength)
  {
    fixedLength--;
    *pDest = getByte(pValue, fixedLength);
    pDest++;
  }

exit:
  return status;

} /* VLONG_fixedByteStringFromVlong */

/*----------------------------------------------------------------------------*/
#ifndef __DISABLE_DIGICERT_VLONG_MATH__

#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || !defined(__DISABLE_DIGICERT_KEY_GENERATION__)

MOC_EXTERN MSTATUS VLONG_mpintByteStringFromVlong (
  const vlong* pValue, 
  ubyte** ppDest, 
  sbyte4* pRetLen
  )
{
  ubyte4 length;
  ubyte4 leadingByte = 0; /* 1 if we need a lead zero or 0xFF byte, 0 otherwise */
  ubyte *pDest = NULL;
  ubyte4 bitLen;
  MSTATUS status = OK;

  if ((NULL == pValue) || (NULL == ppDest) || (NULL == pRetLen))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppDest = NULL;
  *pRetLen = 0;

  if (pValue->numUnitsUsed)
  {
    bitLen = BITLENGTH(pValue->pUnits[pValue->numUnitsUsed - 1]);
    leadingByte = (0 == bitLen % 8) ? 1 : 0;
  }

  /* serialize now */
  if (OK > (status = VLONG_byteStringFromVlong(pValue, NULL,
                                               (sbyte4 *)&length)))
  {
    goto exit;
  }

  pDest = (ubyte *)MALLOC(length + 4 + leadingByte);

  if (!pDest)
  {
    status = ERR_MEM_ALLOC_FAIL;
    goto exit;
  }

  /* length */
  BIGEND32(pDest, length + leadingByte);
  /* leading byte */
  if (leadingByte)
  {
    pDest[4] = (pValue->negative) ? 0xFF : 0x00;
  }

  if (OK > (status =
                VLONG_byteStringFromVlong(pValue, pDest + 4 + leadingByte,
                                          (sbyte4 *)&length)))
  {
    goto exit;
  }

  *pRetLen = length + 4 + leadingByte;
  /* convert to 2 complement if negative */
  if (pValue->negative)
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
  pDest = 0;

exit:
  if (pDest)
  {
    FREE(pDest);
  }

  return status;

} /* VLONG_mpintByteStringFromVlong */

#endif /* __DISABLE_DIGICERT_KEY_GENERATION__ */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_newFromMpintBytes (
  const ubyte *pArray, 
  ubyte4 bytesAvailable,
  vlong **ppNewVlong,  
  ubyte4 *pRetNumBytesUsed,
  vlong **ppVlongQueue
  )
{
  intBoolean isNegativeValue = FALSE;
  sbyte4 length, i;
  vlong *pTmp = NULL;
  MSTATUS status = OK;

  if ((NULL == pArray) || (NULL == ppNewVlong) || (NULL == pRetNumBytesUsed))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppNewVlong = NULL;

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

  *pRetNumBytesUsed = length + 4;

  if (((((sbyte4)bytesAvailable) - 4) < length) || (0 > length))
  {
    status = ERR_BAD_LENGTH;
    goto exit;
  }

  pArray += 4;

  /* over the length */
  /* first byte indicates if the array is negative */
  if (length)
  {
    isNegativeValue = ((*pArray) & 0x80) ? TRUE : FALSE;
  }

  if (OK > (status = VLONG_vlongFromByteString(pArray, length, &pTmp, ppVlongQueue)))
    goto exit;

  DEBUG_RELABEL_MEMORY(pTmp);

  if (isNegativeValue)
  {
    ubyte4 bitLen;

    /* decrement */
    if (OK > (status = VLONG_decrement(pTmp, ppVlongQueue)))
      goto exit;

    /* flip the bits */
    for (i = 0; i < ((sbyte4)pTmp->numUnitsUsed) - 1; ++i)
    {
      pTmp->pUnits[i] ^= FULL_MASK;
    }
    /* last unit is special */
    bitLen = BITLENGTH(pTmp->pUnits[pTmp->numUnitsUsed - 1]);
    pTmp->pUnits[pTmp->numUnitsUsed - 1] ^= (FULL_MASK >> (BPU - bitLen));

    pTmp->negative = TRUE;

    /* update pTmp->numUnitsUsed in case .... */
    while ((pTmp->numUnitsUsed) && (ZERO_UNIT == pTmp->pUnits[pTmp->numUnitsUsed - 1]))
      pTmp->numUnitsUsed--;
  }

  *ppNewVlong = pTmp;
  pTmp = 0;

exit:

  VLONG_freeVlong(&pTmp, ppVlongQueue);
  return status;

} /* VLONG_newFromMpintBytes */
#endif /* __DISABLE_DIGICERT_VLONG_MATH__ */

/*----------------------------------------------------------------------------*/

static ubyte getByte (
  const vlong *pThis, 
  ubyte4 byteIndex
  )
{
  vlong_unit unit = VLONG_getVlongUnit(pThis, byteIndex / (sizeof(vlong_unit)));

  byteIndex %= sizeof(vlong_unit);

  unit >>= (byteIndex << 3);

  return ((ubyte)(unit & 0xff));
}
