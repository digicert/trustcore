/*
 * p1pad.c
 *
 * Pad and unpad following PKCS 1 version 1.5
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

#include "../../../crypto/mocasym.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

MOC_EXTERN MSTATUS RsaPadPkcs15 (
  ubyte *pDataToPad,
  ubyte4 dataToPadLen,
  ubyte4 operation,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pPaddedData,
  ubyte4 bufferSize
  )
{
  MSTATUS status;
  ubyte4 padLen, count, offset;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDataToPad) || (NULL == RngFun) ||
       (NULL == pPaddedData) )
    goto exit;

  /* With P1 padding, we need at least 11 bytes of pad
   * For example, with type 1,
   * 00 01 ff ... ff 00 <data>
   * There must be at least 8 octets of FF, then add in the leading 00 01 and
   * then the 00 that separates the pad from the data, that's 11.
   */
  padLen = bufferSize - dataToPadLen;

  status = ERR_RSA_INVALID_KEY;
  if (11 > padLen)
    goto exit;

  /* These bytes will always be the same.
   */
  pPaddedData[0] = 0;
  pPaddedData[padLen - 1] = 0;

  /* The dataToProcess goes to the end of the buffer
   */
  status = DIGI_MEMCPY (
    (void *)(pPaddedData + padLen), (void *)pDataToPad, dataToPadLen);
  if (OK != status)
    goto exit;

  /* If SIGN, use type 1.
   */
  if (MOC_ASYM_KEY_FUNCTION_SIGN == operation)
  {
    /* This will be 00 01 ff .. ff 00
     */
    pPaddedData[1] = 1;
    status = DIGI_MEMSET (
      (void *)(pPaddedData + 2), 0xFF, padLen - 3);
    goto exit;
  }

  /* This is ENCRPYT, so will be 00 02 <nonzero random> 00
   */
  pPaddedData[1] = 2;
  count = padLen - 3;
  offset = 2;

  /* Generate random bytes. Check that they are all non zero. If there are some
   * zero bytes, generate some more.
   */
  while (count > 0)
  {
    status = RngFun (
      pRngFunArg, count, pPaddedData + offset);
    if (OK != status)
      goto exit;

    /* If we find any 00 bytes, just generate a new batch from the point the 0
     * was found.
     */
    for (; offset < (padLen - 1); ++offset)
    {
      if (0 == pPaddedData[offset])
        break;

      count--;
    }
  }

exit:

  return (status);
}

MOC_EXTERN MSTATUS RsaUnpadPkcs15 (
  ubyte4 operation,
  ubyte *pDataToUnpad,
  ubyte4 dataLen,
  ubyte4 *pUnpadLen,
  ubyte4 *pPadCheck
  )
{
  MSTATUS status;
  ubyte4 index, count;
  ubyte checkType, cmpVal;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDataToUnpad) || (NULL == pUnpadLen) || (NULL == pPadCheck) )
    goto exit;

  /* Init return values: 0 len meaning there is no unpadded data (error), 0
   * padCheck meaning no padding errors found yet.
   */
  *pUnpadLen = 0;
  *pPadCheck = 0;

  status = OK;

  checkType = 1;
  cmpVal = 0xFF;
  if (MOC_ASYM_KEY_FUNCTION_ENCRYPT == operation)
  {
    checkType = 2;
    cmpVal = 0;
  }

  if ( (0 != pDataToUnpad[0]) || (checkType != pDataToUnpad[1]) )
  {
    *pPadCheck |= MOC_ASYM_VFY_FAIL_PAD_BYTES;
  }

  /* Skip the pad bytes until hitting 00.
   * If this is signing, we need to make sure all pad bytes are 0xFF.
   * If encrypting, the bytes should be random.
   * Compare data[i] with data[i-1] (data[1] is init to 0xFF for sign, 0x00 for
   * encrypt).
   * If they are different, increment count.
   */
  index = 2;
  count = 0;
  while ( (index < dataLen) && (0 != pDataToUnpad[index]) )
  {
    if (cmpVal != pDataToUnpad[index])
      count++;

    cmpVal = pDataToUnpad[index];

    index++;
  }

  /* This is now the number of pad bytes.
   */
  index++;

  /* Did we hit not a 00? Or was 00 the last byte so there is no actual data?
   * Are there at least 11 bytes of pad?
   */
  if ( (index >= dataLen) || (11 > index) )
  {
    *pPadCheck |= MOC_ASYM_VFY_FAIL_PAD_LEN;

    /* This is to make sure that dataLen - index >= 0.
     */
    if (index > dataLen)
      index = dataLen;
  }

  /* If this is for encrypt, we should have a big count (the majority of bytes
   * were different than the previous byte). We'll look for at least padLen / 4
   * differences. There's not much more we can do without running some expensive
   * random number tests.
   * If this is for signing, we should have 0 count (all bytes were the same).
   */
  if (MOC_ASYM_KEY_FUNCTION_ENCRYPT == operation)
  {
    if (count < (index >> 2))
    {
      *pPadCheck |= MOC_ASYM_VFY_FAIL_PAD_BYTES;
    }
  }
  else
  {
    if (0 < count)
    {
      *pPadCheck |= MOC_ASYM_VFY_FAIL_PAD_BYTES;
    }
  }

  /* Move the data from after the last byte of pad to the beginning. Because the
   * addresses can overlap, use memmove.
   */
  if ( (index < dataLen) && (0 < index) )
  {
    status = DIGI_MEMMOVE (pDataToUnpad, pDataToUnpad + index, dataLen - index);
    if (OK != status)
      goto exit;
  }

  *pUnpadLen = dataLen - index;

exit:

  if ( (OK != status) && (NULL != pPadCheck) )
  {
    *pPadCheck |= MOC_ASYM_VFY_FAIL_PAD;
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
