/*
 * parsepem.c
 *
 * Functions that parse PEM messages.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../crypto/mocsym.h"
#include "../common/base64.h"

/* Isolate a line and find the start of the next line.
 * <p>This function will look for the next new line character or else the end of
 * the buffer. Once it finds the end of the line, it will determine the count of
 * that line (how many bytes make up the line, this does not include the new line
 * characters). It will then determine the offset to get to the next line. That
 * is, it skips the new line characters.
 * <p>If the function reaches the end of the buffer, it will set *pIsEnd to TRUE
 * and *pNextOffset to 0.
 */
MSTATUS ParsePemGetLine (
  ubyte *pBuffer,
  ubyte4 bufferLen,
  ubyte4 *pLineLen,
  ubyte4 *pNextOffset,
  intBoolean *pIsEnd
  );

MOC_EXTERN MSTATUS BASE64_decodePemMessageAlloc (
  ubyte *pInputPem,
  ubyte4 inputPemLen,
  ubyte4 *pPemType,
  ubyte **ppDerResult,
  ubyte4 *pDerResultLen
  )
{
  MSTATUS status;
  intBoolean isEnd;
  sbyte4 cmpResult;
  ubyte4 index, count, offset, newOffset, newCount;
  ubyte *pTemp = NULL;
  ubyte *pReqH = (ubyte *)MOC_PEM_REQ_HEADER;
  ubyte *pCrtH = (ubyte *)MOC_PEM_CERT_HEADER;
  ubyte *pPubH = (ubyte *)MOC_PEM_PUB_HEADER;
  ubyte *pPriH = (ubyte *)MOC_PEM_PRI_HEADER;
  ubyte *ppHeaders[4] = {
    pReqH, pCrtH, pPubH, pPriH
  };
  ubyte4 pHeaderLen[4] = {
    MOC_PEM_REQ_HEADER_LEN, MOC_PEM_CERT_HEADER_LEN,
    MOC_PEM_PUB_HEADER_LEN, MOC_PEM_PRI_HEADER_LEN
  };
  ubyte4 pTypes[4] = {
    MOC_PEM_TYPE_CERT_REQUEST, MOC_PEM_TYPE_CERT,
    MOC_PEM_TYPE_PUB_KEY, MOC_PEM_TYPE_PRI_KEY
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pInputPem) || (0 == inputPemLen) || (NULL == pPemType) ||
       (NULL == ppDerResult) || (NULL == pDerResultLen) )
    goto exit;

  offset = 0;
  newCount = 0;
  *pPemType = 0;
  *ppDerResult = NULL;
  *pDerResultLen = 0;

  status = ERR_INVALID_INPUT;
  if ('-' != pInputPem[0])
    goto exit;

  /* The Base64 decoder cannot handle new line characters, we'll need to copy the
   * Base64 characters into a continuous buffer.
   */
  status = DIGI_MALLOC ((void **)&pTemp, inputPemLen);
  if (OK != status)
    goto exit;

  while (offset < inputPemLen)
  {
    status = ParsePemGetLine (
      pInputPem + offset, inputPemLen - offset, &count, &newOffset, &isEnd);
    if (OK != status)
      goto exit;

    /* The newOffset was the offset into the buffer given, but the buffer given
     * was pinputPem + offset. So the real newOffset we want is offset +
     * newOffset.
     */
    newOffset += offset;

    /* If this is the first line, determine the header.
     */
    if (0 == offset)
    {
      for (index = 0; index < 4; ++index)
      {
        if (count != pHeaderLen[index])
          continue;

        status = DIGI_MEMCMP (
          (void *)pInputPem, (void *)(ppHeaders[index]), pHeaderLen[index],
          &cmpResult);
        if (OK != status)
          goto exit;

        if (0 != cmpResult)
          continue;

        *pPemType = pTypes[index];
        break;
      }
    }
    else if (0 != count)
    {
      /* Copy this line into the temp buffer.
       */
      status = DIGI_MEMCPY (
        (void *)(pTemp + newCount), (void *)(pInputPem + offset), count);
      if (OK != status)
        goto exit;

      newCount += count;
    }

    /* If we reached the end of the buffer or if the next line is the footer
     * (begins with '-'), we're done reading the input.
     */
    if ( (FALSE != isEnd) || ('-' == pInputPem[newOffset]) )
      break;

    /* Point to the next line.
     */
    offset = newOffset;
  }

  status = BASE64_decodeMessage (
    pTemp, newCount, ppDerResult, pDerResultLen);

exit:

  if (NULL != pTemp)
  {
    DIGI_FREE ((void **)&pTemp);
  }

  return (status);
}

MSTATUS ParsePemGetLine (
  ubyte *pBuffer,
  ubyte4 bufferLen,
  ubyte4 *pLineLen,
  ubyte4 *pNextOffset,
  intBoolean *pIsEnd
  )
{
  ubyte4 index;

  *pNextOffset = 0;
  *pIsEnd = TRUE;

  index = 0;

  /* look at all the characters until the end or finding new line.
   */
  while (index < bufferLen)
  {
    if ( (0x0A == pBuffer[index]) || (0x0D == pBuffer[index]) )
      break;

    index++;
  }

  *pLineLen = index;

  /* If we broke out of the loop because we found a new line, skip the new line
   * characters
   */
  while (index < bufferLen)
  {
    if ( (0x0A != pBuffer[index]) && (0x0D != pBuffer[index]) )
      break;

    index++;
  }

  if (index < bufferLen)
  {
    *pNextOffset = index;
    *pIsEnd = FALSE;
  }

  return (OK);
}
