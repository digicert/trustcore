/*
 * serialcommon.c
 *
 * Functions common among serialization implementations.
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

#include "../crypto/mocasym.h"
#include "../common/base64.h"
#include "../common/serialcommon.h"

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

MOC_EXTERN MSTATUS SerializeCommonInit (
  MSerializeInfo *pInfo,
  serializedKeyFormat format
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pInfo->ppSerializedKey) || (NULL == pInfo->pSerializedKeyLen) )
    goto exit;

  /* Initialize return buffer */
  *(pInfo->ppSerializedKey) = NULL;
  *(pInfo->pSerializedKeyLen) = 0;
  pInfo->derLen = 0;

  /* Default info */
  pInfo->formatToUse = format;
  pInfo->dataToReturn.ppData = pInfo->ppSerializedKey;
  pInfo->dataToReturn.pLength = pInfo->pSerializedKeyLen;
  pInfo->headerLen = MOC_PUB_PEM_HEADER_LEN;
  pInfo->footerLen = MOC_PUB_PEM_FOOTER_LEN;

  /* Check the format and if necessary set fields accordingly */
  switch(format)
  {
    default:
      status = ERR_UNSUPPORTED_OPERATION;
      goto exit;

    case mocanaBlobVersion2:
    case publicKeyInfoDer:
    case privateKeyInfoDer:
      break;

    case publicKeyPem:
      pInfo->formatToUse = publicKeyInfoDer;
      pInfo->dataToReturn.ppData = &(pInfo->pDerEncoding);
      pInfo->dataToReturn.pLength = &(pInfo->derLen);
      pInfo->pHeader = (ubyte *)pInfo->pPubHeader;
      pInfo->pFooter = (ubyte *)pInfo->pPubFooter;
      break;

    case privateKeyPem:
      pInfo->formatToUse = privateKeyInfoDer;
      pInfo->dataToReturn.ppData = &(pInfo->pDerEncoding);
      pInfo->dataToReturn.pLength = &(pInfo->derLen);
      pInfo->pHeader = (ubyte *)pInfo->pPriHeader;
      pInfo->pFooter = (ubyte *)pInfo->pPriFooter;
      pInfo->headerLen = MOC_PRI_PEM_HEADER_LEN;
      pInfo->footerLen = MOC_PRI_PEM_FOOTER_LEN;
  }

  status = OK;

exit:
  return status;

} /* SerializeCommonInit */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SerializeCommon (
  MSerializeInfo *pInfo
  )
{
  MSTATUS status;
  ubyte4 b64Len, totalSize, headerLen, footerLen, nextLen, index;
  ubyte *pB64 = NULL;
  ubyte *pNewBuf = NULL;
  ubyte *pHeader = NULL;
  ubyte *pFooter = NULL;
  ubyte *pCurrent = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pInfo)
    goto exit;

  headerLen = pInfo->headerLen;
  footerLen = pInfo->footerLen;
  pHeader = pInfo->pHeader;
  pFooter = pInfo->pFooter;

  /* The caller wanted PEM.
   * We want to write out header || base 64 || footer.
   * Start by Base64 encoding the actual key data.
   */
  status = BASE64_encodeMessage (
    pInfo->pDerEncoding, pInfo->derLen, &pB64, &b64Len);
  if (OK != status)
    goto exit;

  /* We need to add a new line every 64 characters, and the last line, and the
   * header and footer.
   */
  totalSize = 2 + ((b64Len + 63) / 64);
  totalSize = totalSize + headerLen + footerLen + b64Len;

  status = DIGI_MALLOC ((void **)&pNewBuf, totalSize);
  if (OK != status)
    goto exit;

  /* Header + new line
   */
  index = 0;
  status = DIGI_MEMCPY ((void *)pNewBuf, pHeader, headerLen);
  if (OK != status)
    goto exit;

  pNewBuf[headerLen] = 0x0a;
  index = headerLen + 1;

  pCurrent = pB64;
  while (0 < b64Len)
  {
    /* Copy the next 64 bytes (unless there are fewer than 64 bytes left), then
     * put in the new line character.
     */
    nextLen = b64Len;
    if (64 <= b64Len)
      nextLen = 64;

    status = DIGI_MEMCPY (
      (void *)(pNewBuf + index), (void *)pCurrent, nextLen);
    if (OK != status)
      goto exit;

    pNewBuf[index + nextLen] = 0x0a;
    index += (nextLen + 1);
    b64Len -= nextLen;
    pCurrent += nextLen;
  }

  /* Now put in the footer.
   */
  status = DIGI_MEMCPY (
    (void *)(pNewBuf + index), (void *)pFooter, footerLen);
  if (OK != status)
    goto exit;

  pNewBuf[index + footerLen] = 0x0a;

  *(pInfo->ppSerializedKey) = pNewBuf;
  *(pInfo->pSerializedKeyLen) = totalSize;
  pNewBuf = NULL;

exit:

  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }
  if (NULL != pB64)
  {
    DIGI_FREE ((void **)&pB64);
  }

  return status;

} /* SerializeCommon */

#endif /* (defined(__ENABLE_DIGICERT_SERIALIZE__)) */
