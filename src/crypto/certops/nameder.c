/*
 * nameder.c
 *
 * Functions for DER encoding and decoding an X.500 Name.
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

#include "../../crypto/certops.h"
#include "../../asn1/mocasn1.h"

extern MSTATUS MBuildNameDerAlloc (
  MCertNameElement *pNameArray,
  ubyte4 nameArrayCount,
  ubyte **ppNameDer,
  ubyte4 *pNameDerLen
  )
{
  MSTATUS status;
  ubyte4 index;
  MAsn1Element *pArray = NULL;
  MAsn1Element *pGetElement;
  MSymOperatorData getRdn;
  MAsn1TypeAndCount pTemplate[2] = {
    { MASN1_TYPE_SEQUENCE_OF, 1 },
      { MASN1_TYPE_ENCODED, 0 }
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pNameArray) || (0 == nameArrayCount) ||
       (NULL == ppNameDer) || (NULL == pNameDerLen) )
    goto exit;

  /* A Name is an RDNSequence
   *    SEQUENCE OF {
   *      RelativeDistinguishedName }
   *
   * A RelativeDistinguishedName is
   *    SET OF {
   *      AttributeTypeAndValue }
   *
   * An AttributeTypeAndValue is
   *    SEQUENCE {
   *      type,    -- OID
   *      value    -- ANY }
   * To build the name, we'll call each of the elements in the nameArray to build
   * themselves. That will be the RelativeDistinguishedName. Although an RDN is a
   * SET OF, and can have more than one Attribute, common practice has only one
   * Attribute for each RDN.
   */

  status = MAsn1CreateElementArray (
    pTemplate, 2, MASN1_FNCT_ENCODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  for (index = 0; index < nameArrayCount; ++index)
  {
    /* If this is the first Name element, we're going to set the Element in the
     * original template/array. Otherwise, we need to build a new Element.
     */
    pGetElement = pArray + 1;
    if (0 != index)
    {
      status = MAsn1CopyAddOfEntry (pArray, &pGetElement);
      if (OK != status)
        goto exit;
    }

    getRdn.pData = NULL;
    getRdn.length = 0;
    status = pNameArray[index].NameType (
      MOC_NAME_OP_ENCODE_RDN, pNameArray[index].pValue,
      pNameArray[index].valueLen, (void *)&getRdn);
    if (OK != status)
      goto exit;

    /* Now set the Element with this encoding.
     * We're going to "cheat". We'll set the value.pValue to the data, but we'll
     * also set the buffer.pBuf to this buffer and set bufFlag to indicate the
     * Element should free this memory. This just makes the memory management
     * easier, let the pArray take care of it. We can do this because the
     * EXPLICIT tag is not set (otherwise we would need a pBuf with space in the
     * front for the EXPLICIT tag and length).
     * We also know we don't need to free any existing pBuf because we just
     * created the Element.
     */
    pGetElement->value.pValue = getRdn.pData;
    pGetElement->valueLen = getRdn.length;
    pGetElement->state = MASN1_STATE_SET_COMPLETE;
    pGetElement->buffer.pBuf = getRdn.pData;
    pGetElement->bufFlag |= MASN1_BUF_FLAG_FREE;
  }

  status = MAsn1EncodeAlloc (pArray, ppNameDer, pNameDerLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}
