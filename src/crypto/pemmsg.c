/*
 * pemmsg.c
 *
 * Functions that build PEM messages from DER.
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

#include "../crypto/mocsym.h"
#include "../common/base64.h"

extern MSTATUS BASE64_makePemMessageAlloc (
  ubyte4 pemType,
  ubyte *pInputDer,
  ubyte4 inputDerLen,
  ubyte **ppPemResult,
  ubyte4 *pPemResultLen
  )
{
  MSTATUS status;
  ubyte4 headerLen, footerLen, b64Len, totalSize, index, nextLen;
  ubyte *pB64 = NULL;
  ubyte *pNewBuf = NULL;
  ubyte *pHeader, *pFooter, *pCurrent;
  ubyte *pReqH = (ubyte *)MOC_PEM_REQ_HEADER;
  ubyte *pReqF = (ubyte *)MOC_PEM_REQ_FOOTER;
  ubyte *pCrtH = (ubyte *)MOC_PEM_CERT_HEADER;
  ubyte *pCrtF = (ubyte *)MOC_PEM_CERT_FOOTER;
  ubyte *pPubH = (ubyte *)MOC_PEM_PUB_HEADER;
  ubyte *pPubF = (ubyte *)MOC_PEM_PUB_FOOTER;
  ubyte *pPriH = (ubyte *)MOC_PEM_PRI_HEADER;
  ubyte *pPriF = (ubyte *)MOC_PEM_PRI_FOOTER;
  ubyte *pEncPriH = (ubyte *)MOC_PEM_ENCR_PRI_HEADER;
  ubyte *pEncPriF = (ubyte *)MOC_PEM_ENCR_PRI_FOOTER;
  ubyte *pPriTapH = (ubyte *)MOC_PEM_PRI_TAP_HEADER;
  ubyte *pPriTapF = (ubyte *)MOC_PEM_PRI_TAP_FOOTER;

  status = ERR_NULL_POINTER;
  if ( (NULL == pInputDer) || (0 == inputDerLen) ||
       (NULL == ppPemResult) || (NULL == pPemResultLen) )
    goto exit;

  switch (pemType)
  {
    default:
      status = ERR_INVALID_INPUT;
      goto exit;

    case MOC_PEM_TYPE_CERT_REQUEST:
    case MOC_PEM_TYPE_CERT_REQUEST_ONE_LINE:
      pHeader = pReqH;
      pFooter = pReqF;
      headerLen = MOC_PEM_REQ_HEADER_LEN;
      footerLen = MOC_PEM_REQ_FOOTER_LEN;
      break;

    case MOC_PEM_TYPE_CERT:
    case MOC_PEM_TYPE_CERT_ONE_LINE:
      pHeader = pCrtH;
      pFooter = pCrtF;
      headerLen = MOC_PEM_CERT_HEADER_LEN;
      footerLen = MOC_PEM_CERT_FOOTER_LEN;
      break;

    case MOC_PEM_TYPE_PUB_KEY:
      pHeader = pPubH;
      pFooter = pPubF;
      headerLen = MOC_PEM_PUB_HEADER_LEN;
      footerLen = MOC_PEM_PUB_FOOTER_LEN;
      break;

    case MOC_PEM_TYPE_PRI_KEY:
      pHeader = pPriH;
      pFooter = pPriF;
      headerLen = MOC_PEM_PRI_HEADER_LEN;
      footerLen = MOC_PEM_PRI_FOOTER_LEN;
      break;

    case MOC_PEM_TYPE_ENCR_PRI_KEY:
      pHeader = pEncPriH;
      pFooter = pEncPriF;
      headerLen = MOC_PEM_ENCR_PRI_HEADER_LEN;
      footerLen = MOC_PEM_ENCR_PRI_FOOTER_LEN;
      break;

    case MOC_PEM_TYPE_PRI_TAP_KEY:
      pHeader = pPriTapH;
      pFooter = pPriTapF;
      headerLen = MOC_PEM_PRI_TAP_HEADER_LEN;
      footerLen = MOC_PEM_PRI_TAP_FOOTER_LEN;
      break;
  }

  /* We want to write out header || base 64 || footer.
   * Start by Base64 encoding the actual data.
   */
  status = BASE64_encodeMessage (
    pInputDer, inputDerLen, &pB64, &b64Len);
  if (OK != status)
    goto exit;

  /* We need to add a new line every 64 characters, ...
   * If it is a ONE_LINE PEM, then each new-line is actually two chars: "\"+"n"
   */
  totalSize = 2 + ((b64Len + 63) / 64);
  if (MOC_PEM_TYPE_CERT_ONE_LINE == pemType || MOC_PEM_TYPE_CERT_REQUEST_ONE_LINE == pemType)
  {
    totalSize = totalSize + 2 + ((b64Len + 63) / 64);
  }

  /* We need to add a new line every 64 characters, and the last line, and the
   * header and footer.
   */
  totalSize = totalSize + headerLen + footerLen + b64Len;

  status = DIGI_MALLOC ((void **)&pNewBuf, totalSize + 1);
  if (OK != status)
    goto exit;

  /* Header + new line
   */
  status = DIGI_MEMCPY ((void *)pNewBuf, pHeader, headerLen);
  if (OK != status)
    goto exit;

  if (MOC_PEM_TYPE_CERT_ONE_LINE == pemType || MOC_PEM_TYPE_CERT_REQUEST_ONE_LINE == pemType)
  {
      pNewBuf[headerLen] ='\\';
      pNewBuf[headerLen + 1] ='n';
      index = headerLen + 2;
  }
  else
  {
      pNewBuf[headerLen] = 0x0a;
      index = headerLen + 1;
  }

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

    if (MOC_PEM_TYPE_CERT_ONE_LINE == pemType || MOC_PEM_TYPE_CERT_REQUEST_ONE_LINE == pemType)
    {
        pNewBuf[index + nextLen] ='\\';
        pNewBuf[index + nextLen + 1] ='n';
        index += (nextLen + 2);
    }
    else
    {
        pNewBuf[index + nextLen] = 0x0a;
        index += (nextLen + 1);
    }

    b64Len -= nextLen;
    pCurrent += nextLen;
  }

  /* Now put in the footer.
   */
  status = DIGI_MEMCPY (
    (void *)(pNewBuf + index), (void *)pFooter, footerLen);
  if (OK != status)
    goto exit;

  if (MOC_PEM_TYPE_CERT_ONE_LINE == pemType || MOC_PEM_TYPE_CERT_REQUEST_ONE_LINE == pemType)
  {
      /* One line doesn't need a trailing newline */
      pNewBuf[index + footerLen] = 0;
  }
  else
  {
      pNewBuf[index + footerLen] = 0x0a;
      pNewBuf[index + footerLen + 1] = 0;
  }

  *ppPemResult = pNewBuf;
  *pPemResultLen = index + footerLen + 1;
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

  return (status);
}
