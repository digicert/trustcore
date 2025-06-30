/*
 * mocencode.c
 *
 * DER encode.
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

#include "../asn1/mocasn1.h"

/* Check this Element to see if it is available for DER encoding.
 * If this is constructed, it will check the sub Elements.
 * The caller passes in 0 or MASN1_NO_VALUE_SKIP for the setEmpty.
 * If 0, just check.
 * If NO_VALUE_SKIP, set this Element to be empty and not to be written out (it
 * is a subElement to a constructed that will not be written out).
 * The state must be NONE, SET_LEN, or SET_COMPLETE. If SET_LEN or SET_COMPLETE,
 * and the tag and length have not been computed, compute it.
 * If there is no value and this is OPTIONAL, make sure the NO_VALUE bit is set.
 * Note that this will check to see if it is available for DER, not if it is
 * available for an all-in-one Encode. For example, suppose an Element has the
 * length set, but not the data. Call this function and it will be good. But if
 * you then try to Encode (not Update), you'll get an error.
 */
MSTATUS MCheckElementForDer (
  MAsn1Element *pElement,
  ubyte4 setEmpty
  );

MSTATUS MAsn1EncodeAlloc (
  MAsn1Element *pElement,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 eLen;
  ubyte *pBuffer = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppEncoding) || (NULL == pEncodingLen) )
    goto exit;

  *ppEncoding = NULL;
  *pEncodingLen = 0;

  /* If this returns OK, then there was no encoding (not likely but possible, if
   * an Element is OPTIONAL).
   * If there is an error other than BUFFER_TOO_SMALL, return that error.
   */
  status = MAsn1Encode (pElement, NULL, 0, &eLen);
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  status = MOC_MALLOC ((void **)&pBuffer, eLen);
  if (OK != status)
    goto exit;

  status = MAsn1Encode (pElement, pBuffer, eLen, &eLen);
  if (OK != status)
    goto exit;

  *ppEncoding = pBuffer;
  *pEncodingLen = eLen;
  pBuffer = NULL;

exit:

  if (NULL != pBuffer)
  {
    MOC_FREE ((void **)&pBuffer);
  }

  return (status);
}

MOC_EXTERN MSTATUS MAsn1Encode (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  intBoolean isComplete;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement) || (NULL == pEncodingLen) )
    goto exit;

  /* Check the first Element to make sure it was set up to ENCODE. We'll assume
   * if the first one was set properly, the rest were as well (assuming the
   * caller used the Create function).
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_ENCODE))
    goto exit;

  /* Make sure all the elements are set up to DER encode.
   */
  status = MCheckElementForDer (pElement, 0);
  if (OK != status)
    goto exit;

  /* Call the Encode Indef. If everything is set correctly, this will do DER of
   * definite length.
   */
  status = MAsn1EncodeIndefiniteUpdate (
    pElement, pEncoding, bufferSize, pEncodingLen, &isComplete);
  if (OK != status)
    goto exit;

  /* We have to be complete. If not, error.
   */
  status = ERR_ASN_INVALID_STATE;
  if (FALSE != isComplete)
    status = OK;

exit:

  return (status);
}

MSTATUS MAsn1EncodeUpdate (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen,
  intBoolean *pIsComplete
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement) || (NULL == pEncodingLen) || (NULL == pIsComplete) )
    goto exit;

  /* Check the first Element to make sure it was set up to ENCODE. We'll assume
   * if the first one was set properly, the rest were as well (assuming the
   * caller used the Create function).
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_ENCODE))
    goto exit;

  /* Make sure all the elements are set up to DER encode.
   */
  status = MCheckElementForDer (pElement, 0);
  if (OK != status)
    goto exit;

  /* Call the Encode Indef. If everything is set correctly, this will do DER of
   * definite length.
   */
  status = MAsn1EncodeIndefiniteUpdate (
    pElement, pEncoding, bufferSize, pEncodingLen, pIsComplete);

exit:

  return (status);
}

MSTATUS MCheckElementForDer (
  MAsn1Element *pElement,
  ubyte4 setEmpty
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 newState, newEmpty, count;
  MAsn1Element *pNext;
  MAsn1OfEntry *pOfEntry = NULL;

  /* Has it already been checked?
   */
  status = OK;
  newState = pElement->state;
  if (0 != (pElement->bufFlag & MASN1_BUF_FLAG_DER_CHECK))
    goto exit;

  /* If everything works, the newState will be SET_COMPLETE.
   * Unless the state is SET_LEN or SET_PARTIAL, in which case it will
   * stay that state.
   */
  if ((MASN1_STATE_SET_LEN != pElement->state) &&
      (MASN1_STATE_SET_PARTIAL != pElement->state))
    newState = MASN1_STATE_SET_COMPLETE;

  newEmpty = MASN1_NO_VALUE_SKIP;
  if (0 == setEmpty)
  {
    /* The state must be NONE, SET_LEN, SET_PARTIAL, SET_COMPLETE, or ENCODE_COMPLETE. It will
     * be ENCODE_COMPLETE if it is empty.
     */
    status = ERR_ASN_INVALID_STATE;
    if ( (MASN1_STATE_ENCODE_COMPLETE != pElement->state) &&
         (MASN1_STATE_SET_COMPLETE != pElement->state) &&
         (MASN1_STATE_SET_LEN != pElement->state) &&
         (MASN1_STATE_SET_PARTIAL != pElement->state) &&
         (MASN1_STATE_NONE != pElement->state) )
      goto exit;

    /* For DER, there are some type bits that are not allowed.
     */
    if (0 != (pElement->type & (MASN1_UNKNOWN_VALUE | MASN1_UNKNOWN_OF)))
      goto exit;

    newEmpty = pElement->type & MASN1_NO_VALUE_SKIP;
  }

  status = OK;
  pElement->type |= newEmpty;

  /* If this is constructed, we have to check the subElements.
   */
  if (0 != (pElement->type & MASN1_CONSTRUCTED_MASK))
  {
    /* Get the first subElement. We assume there is one otherwise the Create
     * would not have succeeded.
     */
    pNext = pElement + 1;
    if (0 != (pElement->type & MASN1_TYPE_OF))
      pOfEntry = &(pElement->value.pOfTemplate->entry);

    count = pElement->valueLen;
    do
    {
      status = MCheckElementForDer (pNext, newEmpty);
      if (OK != status)
        goto exit;

      if (NULL == pOfEntry)
      {
        count--;
        pNext = (MAsn1Element *)(pNext->pNext);
        if (0 == count)
          break;
      }
      else
      {
        pOfEntry = (MAsn1OfEntry *)(pOfEntry->pNext);
        pNext = NULL;
        if (NULL != pOfEntry)
          pNext = pOfEntry->pElement;
      }
    } while (NULL != pNext);

    goto exit;
  }

  /* This is not constructed. If the newEmpty val is not SKIP, make sure the tag
   * and len are set.
   */
  if ( (MASN1_NO_VALUE_SKIP != newEmpty) && (0 == pElement->bufLen) )
  {
    /* It's possible someone simply did not set this Element in order to indicate
     * no value (rather than calling SetValueLenSpecial). If so, make sure the
     * NO_VALUE bit is set.
     */
    if ( (0 == pElement->valueLen) && (0 == pElement->encoding.remaining) )
      pElement->type |= MASN1_NO_VALUE;

    status = MAsn1ComputeTagAndLenIndef (pElement, 0, &isComplete, &count);
  }

exit:

  /* If we this function was successful, mark it as so and we can set the state
   * to COMPLETE (if that is the new state).
   */
  if (OK == status)
  {
    pElement->bufFlag |= MASN1_BUF_FLAG_DER_CHECK;
    pElement->state = newState;
  }

  return (status);
}
