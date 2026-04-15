/*
 * timeasn1.c
 *
 * Operate on UTCTime and GeneralizedTime.
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
 */

#include "../asn1/mocasn1.h"
#include "../common/datetime.h"

MSTATUS MAsn1SetTime (
  MAsn1Element *pTimeElement,
  TimeDate *pTime
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 fullYear, offset, theTag;

  status = ERR_NULL_POINTER;
  if ( (NULL == pTimeElement) || (NULL == pTime) )
    goto exit;

  theTag = pTimeElement->type & MASN1_TYPE_MASK;
  status = ERR_ASN_INVALID_TAG_INFO;
  if ( (MASN1_TYPE_UTC_TIME != theTag) && (MASN1_TYPE_GEN_TIME != theTag) &&
       (MASN1_TYPE_ANY_TIME != theTag) )
    goto exit;

  /* Make sure this Element was set up to encode.
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (NULL == pTimeElement->buffer.pBuf)
    goto exit;

  fullYear = 1970 + (ubyte4)(pTime->m_year);

  /* The conversion function will convert to 2 char year (UTCTime) or 4 char year
   * (GenTime), depending on the year. Pre-2049: 2 char, 2049 and later: 4 char.
   * Also, if this is ANY_TIME, make sure the tag we use is based on the year.
   */
  offset = 4;
  if (2049 > fullYear)
  {
    offset = 6;
    if (MASN1_TYPE_ANY_TIME == theTag)
      theTag = MASN1_TYPE_UTC_TIME;
  }
  else
  {
    if (MASN1_TYPE_ANY_TIME == theTag)
      theTag = MASN1_TYPE_GEN_TIME;
  }

  status = DATETIME_convertToValidityString (
    pTime, (sbyte *)(pTimeElement->buffer.pBuf + offset));
  if (OK != status)
    goto exit;

  /* If the element is UTCTime, then we need to point to offset of 6. If we have
   * computed 4 char year, we still only report 2 chars.
   */
  if (MASN1_TYPE_UTC_TIME == theTag)
  {
    pTimeElement->value.pValue = pTimeElement->buffer.pBuf + 6;
    pTimeElement->valueLen = 13;
  }
  else
  {
    /* At this point, we want a 4-char year. If we have one, just point to it. If
     * not, we need to build the first 2 chars.
     */
    if (6 == offset)
    {
      fullYear /= 100;
      pTimeElement->buffer.pBuf[5] = (ubyte)((fullYear % 10) + 0x30);
      fullYear /= 10;
      pTimeElement->buffer.pBuf[4] = (ubyte)(fullYear + 0x30);
    }

    pTimeElement->value.pValue = pTimeElement->buffer.pBuf + 4;
    pTimeElement->valueLen = 15;
  }

  pTimeElement->state = MASN1_STATE_SET_COMPLETE;
  status = MAsn1ComputeTagAndLenIndef (pTimeElement, 0, &isComplete, &offset);
  if (OK != status)
    goto exit;

exit:

  return (status);
}
