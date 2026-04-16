/*
 * getissuerserial.c
 *
 * Functions for getting the IssuerAndSerialNumber out of a cert object.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#include "../../crypto/certops.h"
#include "../../common/base64.h"
#include "../../crypto/certops/certobj.h"

extern MSTATUS MGetIssuerSerial (
  MCertObj pCertObj,
  ubyte **ppIssuerSerial,
  ubyte4 *pIssuerSerialLen
  )
{
  MSTATUS status;
  ubyte4 newBufLen;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pCertObj;
  ubyte *pNewBuf = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[3] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_ENCODED, 0 }
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertObj) || (NULL == ppIssuerSerial) ||
       (NULL == pIssuerSerialLen) )
    goto exit;

  if (NULL == pObj->pArray)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
    goto exit;

  /* Has the issuerSerial already been computed?
   * If the answer is ERR_NOT_FOUND, we'll compute the issuerSerial.
   * If the return is OK, then we have the answer, we're done, just exit.
   * If the return is any other error, return that error.
   */
  status = MGetMemoryInfoCertObject (
    pObj, MOC_CERT_OBJ_MEM_ISSUER_SERIAL, (void **)ppIssuerSerial,
    pIssuerSerialLen);
  if (ERR_NOT_FOUND != status)
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplate, 3, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue =
    pObj->pArray[MOC_CERT_ARRAY_INDEX_ISSNAME].encoding.pEncoding;
  pArray[1].valueLen = pObj->pArray[MOC_CERT_ARRAY_INDEX_ISSNAME].encodingLen;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;
  pArray[2].value.pValue =
    pObj->pArray[MOC_CERT_ARRAY_INDEX_SERIAL_NUM].encoding.pEncoding;
  pArray[2].valueLen = pObj->pArray[MOC_CERT_ARRAY_INDEX_SERIAL_NUM].encodingLen;
  pArray[2].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1EncodeAlloc (pArray, &pNewBuf, &newBufLen);
  if (OK != status)
    goto exit;

  *ppIssuerSerial = pNewBuf;
  *pIssuerSerialLen = newBufLen;

  status = MLoadMemoryIntoCertObject (
    pObj, MOC_CERT_OBJ_MEM_ISSUER_SERIAL, (void **)&pNewBuf, newBufLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}
