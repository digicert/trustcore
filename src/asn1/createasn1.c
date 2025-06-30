/*
 * createasn1.c
 *
 * Create and Free Element array.
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

#define MASN1_MAX_SUB_COUNT   0xffff
#define MASN1_SUB_COUNT_MASK  0xffff

#if (!defined(__DISABLE_MOCANA_ASN1_CREATE_ELEMENT_ARRAY__))

/* How much extra space does this Element need.
 * The last field in the Element is pBuf, which generally holds the tag and
 * length, but can also hold other info, such as a BIT STRING's unused bits, or
 * even the actual encoded value, such as a BOOLEAN or Time.
 * This function determines, based on the tag, how big the pBuf, or extra data
 * beyond the sizeof Element, that will be needed.
 */
MSTATUS GetExtraSpace (
  ubyte4 asn1Fnct,
  ubyte4 tagSpecial,
  ubyte4 subCount,
  ubyte4 arrayCount,
  MOfFunction OfFunction,
  ubyte4 *pExtra
  );

/* Determine which is the next Element.
 * For a non-constructed, the next Element is the next in the list.
 * For a constructed, it is the Element after the completion of its sub Elements.
 * The function will determine if the current Element is constructed or not or
 * the last Element in the list.
 * If the last, it will set *ppNext to NULL.
 * Otherwise, if not constructed, it will set *ppNext to pElement + 1.
 * Otherwise, it will find the next for each of the sub Elements (recursion) and
 * set *ppNext to the next of the last Element.
 * In addition, if an Element is constructed, and the asn1Fnct is ENCODE_INDEF,
 * it will set pElement->encoding.pNext to the next.
 * Finally, the function determines if the array is correct. Namely, that there
 * are indeed n sub Elements for each constructed.
 *
 * For example, consider the following pArray
 *   SEQ {               0
 *     OID               1
 *     SEQ {             2
 *       INT             3
 *       UTF8String      4
 *     }
 *     OCT STRING        5
 *   }
 *
 *  GetNextElement (pArray, &pNext)
 *
 * It will determine that for the Element at 0, there is no next, so it makes
 * sure pElement->pNext is NULL and sets
 *
 *  **ppNext = NULL.
 *
 * While computing the next for the SEQUENCE, the function had to determine the
 * next for each Element.
 *
 *  index = 1;
 *  GetNextElement (pArray + index, &pNext);
 *
 * and so on.
 *
 *   index         *ppNext
 *            pArray[index].pNext
 *  ----------------------------------------------
 *     0            NULL
 *     1           pArray + 2
 *     2           pArray + 5
 *     3           pArray + 4
 *     4           pArray + 5
 *     5            NULL
 *
 * This function does no arg checking. Make sure that any Element you pass in is
 * indeed valid (not beyond the end).
 */
MSTATUS GetNextElement (
  MAsn1Element *pElement,
  MAsn1Element **ppNext
  );

MOC_EXTERN MSTATUS MAsn1CreateElementArray (
  MAsn1TypeAndCount *pDefinition,
  ubyte4 count,
  ubyte4 asn1Fnct,
  MOfFunction OfFunction,
  MAsn1Element **ppNewArray
  )
{
  MSTATUS status;
  ubyte4 index, extra, totalExtra, availableSize, alignment;
  ubyte4 clearCount, tagCheck;
  ubyte *pBuf = NULL;
  ubyte *pAvailable;
  MAsn1Element *pArray, *pNext;

  /* How many Elements do we need to clear (later on we'll adjust the
   * pDefinition[index].count field)? If 0, none. Later on, we'll reset this to
   * count if we need to clear any.
   * The bits we clear are bits we are going to add to the definition entries
   * passed in (the number of extra bytes allocated).
   */
  clearCount = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDefinition) || (NULL == ppNewArray) || (0 == count) )
    goto exit;

  status = ERR_INVALID_ARG;
  if ( (MASN1_FNCT_DECODE != asn1Fnct) && (MASN1_FNCT_ENCODE != asn1Fnct) &&
       (MASN1_FNCT_ENCODE_INDEF != asn1Fnct) )
    goto exit;

  /* The last Element is not allowed to be constructed.
   */
  if (0 != (pDefinition[count - 1].tagSpecial & MASN1_CONSTRUCTED_MASK))
    goto exit;

  *ppNewArray = NULL;
  clearCount = count;

  /* We need to allocate space for count MAsn1Elements, and the buffers for each
   * Type.
   * So first, go through the list of Types to get the space needed.
   */
  totalExtra = 0;
  for (index = 0; index < count; ++index)
  {
    status = GetExtraSpace (
      asn1Fnct, pDefinition[index].tagSpecial, pDefinition[index].count,
      count - (index + 1), OfFunction, &extra);
    if (OK != status)
      goto exit;

    /* Store the extra in the definition (for now).
     */
    pDefinition[index].count |= (extra << 24);

    totalExtra += extra;
  }

  status = MOC_CALLOC (
    (void **)&pBuf, (count * sizeof (MAsn1Element)) + totalExtra, 1);
  if (OK != status)
    goto exit;

  pArray = (MAsn1Element *)pBuf;

  /* Point to the area after array for use as pBuf in each Element.
   */
  pAvailable = pBuf + (count * sizeof (MAsn1Element));
  availableSize = totalExtra;

  /* Now set up each of the Elements.
   */
  for (index = 0; index < count; ++index)
  {
    extra = pDefinition[index].count >> 24;
    pArray[index].type = pDefinition[index].tagSpecial;
    pArray[index].bufFlag |= asn1Fnct;

    status = ERR_BAD_LENGTH;
    if (extra > availableSize)
      goto exit;

    tagCheck = pArray[index].type & MASN1_TAG_MASK;

    /* If this is OF, load an OfTemplate.
     */
    if (0 != (MASN1_TYPE_OF & pDefinition[index].tagSpecial))
    {
      /* Make sure the address is aligned.
       */
      alignment = ((uintptr)pAvailable) & 15;
      alignment = (16 - alignment) & 15;
      pArray[index].value.pOfTemplate = (MAsn1OfTemplate *)(pAvailable + alignment);
      pAvailable += sizeof (MAsn1OfTemplate) + alignment;
      availableSize -= (ubyte4)(sizeof (MAsn1OfTemplate) + alignment);

      /* Init the Of Template. It contains the OfFunction and the first OfEntry.
       */
      pArray[index].value.pOfTemplate->OfFunction = OfFunction;

      /* There should be 1 Element after the OF, it is the template for the group
       * of Elements that will make up the OF. If this OF is the last element in
       * the list, that would have been an error earlier.
       */
      pArray[index].value.pOfTemplate->entry.pElement = pArray + index + 1;

      /* This is how much space we allocated for the OF, make sure extra knows
       * not to count that when building pBuf.
       */
      extra -= (sizeof (MAsn1OfTemplate) + 16);
    }

    /* Set the indef allowed bit for those tags for which indefinite is allowed.
     * Set this only for non-constructed types that can be indef. All constructed
     * types can be indefinite.
     */
    if ( (MASN1_TYPE_BIT_STRING == tagCheck) ||
         (MASN1_TYPE_OCTET_STRING == tagCheck) ||
         (MASN1_TYPE_UTF8_STRING == tagCheck) ||
         (MASN1_TYPE_PRINT_STRING == tagCheck) ||
         (MASN1_TYPE_IA5_STRING == tagCheck) ||
         (MASN1_TYPE_BMP_STRING == tagCheck) )
      pArray[index].type |= MASN1_TYPE_INDEF_ALLOWED;

    pArray[index].valueLen = (pDefinition[index].count & MASN1_SUB_COUNT_MASK);

    if (0 != extra)
    {
      pArray[index].buffer.pBuf = pAvailable;
      availableSize -= extra;
      pAvailable += extra;
    }
  }

  pNext = pArray;

  /* Set the bufFlag of the last element to MASN1_BUF_FLAG_LAST.
   */
  pArray[count - 1].bufFlag |= MASN1_BUF_FLAG_LAST;

  /* Find the next Element for each of the Elements. For the constructed
   * Elements, this function will Store it in pElement->value.pNext or
   * pElement->value.pOfTemplate->pNext.
   */
  while (NULL != pNext)
  {
    status = GetNextElement (pNext, &pNext);
    if (OK != status)
      goto exit;
  }

  *ppNewArray = pArray;
  pBuf = NULL;
  status = OK;

exit:

  for (index = 0; index < clearCount; ++index)
  {
    pDefinition[index].count &= 0x00ffffff;
  }

  if (NULL != pBuf)
  {
    MOC_FREE ((void **)&pBuf);
  }

  return (status);
}

MOC_EXTERN MSTATUS MAsn1FreeElementArray (
  MAsn1Element **ppArray
  )
{
  MSTATUS status, fStatus;
  MAsn1Element *pCurrent, *pNext;

  /* If there's nothing to free, do nothing.
   */
  status = OK;
  if (NULL == ppArray)
    goto exit;

  if (NULL == *ppArray)
    goto exit;

  pNext = *ppArray;

  /* Run through the list, freeing any buffers that were allocated.
   * The bufFlag will also have a flag to indicate which is the last in this
   * array.
   */
  do
  {
    pCurrent = pNext;

    if (0 != (MASN1_TYPE_OF & pCurrent->type))
    {
      if (NULL != pCurrent->value.pOfTemplate)
      {
        if (NULL != pCurrent->value.pOfTemplate->OfFunction)
        {
          fStatus = pCurrent->value.pOfTemplate->OfFunction (
            (struct MAsn1OfEntry *)&(pCurrent->value.pOfTemplate->entry), MASN1_OF_FREE,
            NULL, NULL);
          if (OK == status)
            status = fStatus;
        }
      }
    }

    pNext = NULL;
    if (0 == (pCurrent->bufFlag & MASN1_BUF_FLAG_LAST))
      pNext = pCurrent + 1;

    if (0 != (pCurrent->bufFlag & MASN1_BUF_FLAG_FREE))
    {
      fStatus = MOC_MEMSET_FREE (
        (ubyte **)&(pCurrent->buffer.pBuf), pCurrent->bufLen);
      if (OK == status)
        status = fStatus;
    }
  } while (NULL != pNext);

  /* Now free the entire buffer.
   */
  fStatus = MOC_FREE ((void **)ppArray);
  if (OK == status)
    status = fStatus;

exit:

  return (status);
}

MSTATUS GetExtraSpace (
  ubyte4 asn1Fnct,
  ubyte4 tagSpecial,
  ubyte4 subCount,
  ubyte4 arrayCount,
  MOfFunction OfFunction,
  ubyte4 *pExtra
  )
{
  MSTATUS status;
  ubyte4 tag, tagX, ofTag, addT, addX, sCount;

  /* If the tag is ENCODED, don't look at the actual tag. The caller might not
   * set an actual tag, they might. But at this point, if it is ENCODED, that's
   * all the info we need.
   * If it isn't ENCODED, get the tag.
   */
  tag = tagSpecial & MASN1_TYPE_ENCODED;
  tagX = tagSpecial & MASN1_EXPLICIT;
  if (MASN1_TYPE_NONE == tag)
    tag = tagSpecial & MASN1_TAG_MASK;

  ofTag = tagSpecial & MASN1_TYPE_OF;

  /* If we don't have a tag, it should be ENCODED or ANY_TIME.
   */
  if (MASN1_TYPE_NONE == tag)
    tag = tagSpecial & (MASN1_TYPE_ENCODED | MASN1_TYPE_ANY_TIME);

  status = ERR_ASN_INVALID_TAG_INFO;
  /* How much space to add for EXPLICIT (if the Element is indeed EXPLICIT).
   */
  addX = 0;
  sCount = subCount;
  switch (tag)
  {
    default:
      goto exit;

    case MASN1_TYPE_ENCODED:
      /* If ENCODED, it can't also be ANY_TIME or IMPLICIT or have a tag.
       */
      if (0 != (tagSpecial & (MASN1_TAG_MASK | MASN1_IMPLICIT)))
        goto exit;

      /* We don't really need a pBuf for ENCODED, but this is how we check to see
       * if an Element was init to encode, so create a buffer just to pass the
       * checks.
       */
      addT = 1;
      addX = 6;
      break;

    case MASN1_TYPE_BOOLEAN:
      addT = 3;
      addX = 2;
      break;

    case MASN1_TYPE_INTEGER:
      /* For INTEGER, we want to make sure we have enough space to load an
       * sbyte4. In order to know which index in the pBuf we use to load the 4
       * bytes, make sure the default is 8 bytes. That way if it is EXPLICIT, we
       * start loading an sbyte4 at index 4. If it's not EXPLICIT, we start
       * loading an sbyte4 at index 4, even though we could have started at index
       * 2, but it doesn't matter, when encoding we're going to write out the
       * data based on value.pValue.
       */
      addT = 8;
      addX = 5;
      break;

    case MASN1_TYPE_BIT_STRING:
      addT = 7;
      addX = 6;
      break;

    case MASN1_TYPE_OCTET_STRING:
      addT = 6;
      addX = 6;
      break;

    case MASN1_TYPE_NULL:
      addT = 2;
      addX = 2;
      break;

    case MASN1_TYPE_OID:
      /* This assumes we'll never see an OID longer than 0x7D with EXPLICIT or 7F
       * without.
       */
      addT = 2;
      addX = 2;
      break;

    case MASN1_TYPE_UTF8_STRING:
    case MASN1_TYPE_PRINT_STRING:
    case MASN1_TYPE_IA5_STRING:
    case MASN1_TYPE_BMP_STRING:
      addT = 6;
      addX = 6;
      break;

    case MASN1_TYPE_ANY_TIME:
    case MASN1_TYPE_UTC_TIME:
      /* UTC Time needs 2 fewer bytes than GenTime, however, our code always
       * builds GenTime and if UTC, skips the 2 extra year bytes. So we still
       * need the same amount of space.
       * Also, we're going to use the space after the tag and len. Just to make
       * it easier to know where to begin using the buffer, just start 4 bytes in
       * (the EXPLICIT tag and len plus regular tag and len will never be more
       * than 4 bytes). So just always create a 20-byte buffer.
       */
    case MASN1_TYPE_GEN_TIME:
      addT = 20;
      addX = 0;
      break;

    case MASN1_TYPE_SET:
    case MASN1_TYPE_SEQUENCE:
      /* In the real world, the count will be small, but just to be safe, set the
       * limit somewhat high.
       * Also, the count cannot be more than the number of elements in the array.
       */
      if ( (0 == sCount) || (MASN1_MAX_SUB_COUNT < sCount) ||
           (arrayCount < sCount) )
        goto exit;

      /* Once that passed, set sCount to 0, so we can make a check later.
       * sCount was init to subCount. If that were 0, we already returned an error.
       * If we're not in this case, we're in non-constructed and we won't reset
       * sCount (it will still be subCount). If sCount is not 0, in that case,
       * error. So to prepare for that check, set sCount to 0.
       */
      sCount = 0;

      addT = 6;
      addX = 6;
      break;
  }

  /* For non-constructed, the subCount must be 0.
   */
  if (0 != sCount)
    goto exit;

  /* If EXPLICIT, cannot also be IMPLICIT.
   * Add in the extra the EXPLICIT will need.
   */
  if (0 != tagX)
  {
    if (0 != (MASN1_IMPLICIT & tagSpecial))
      goto exit;

    addT += addX;
  }

  /* If we're decoding, we don't actually add any extra data.
   * Unless it's for OF.
   */
  if (MASN1_FNCT_DECODE == asn1Fnct)
    addT = 0;

  /* If OF, must be SET or SEQUENCE, and must have the OfFunction.
   * Also add in the sizeof the MAsn1OfTemplate (along with space for alignment).
   */
  if (0 != ofTag)
  {
    if ( (MASN1_TYPE_SEQUENCE != tag) && (MASN1_TYPE_SET != tag) )
      goto exit;

    if (NULL == OfFunction)
      goto exit;

    addT += (sizeof (MAsn1OfTemplate) + 16);
  }

  *pExtra = addT;

  status = OK;

exit:

  return (status);
}

MSTATUS GetNextElement (
  MAsn1Element *pElement,
  MAsn1Element **ppNext
  )
{
  MSTATUS status;
  ubyte4 count;
  MAsn1Element *pNext;

  pNext = NULL;
  status = ERR_ASN_INVALID_TAG_INFO;
  if (NULL == pElement)
    goto exit;

  status = OK;
  if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_LAST))
    pNext = pElement + 1;

  /* If this is constructed, valueLen is the number of sub Elements.
   * If not, we have the answer already in pNext.
   */
  count = pElement->valueLen;
  if (0 == (pElement->type & MASN1_CONSTRUCTED_MASK))
    goto exit;

  while (count > 0)
  {
    status = GetNextElement (pNext, &pNext);
    if (OK != status)
      goto exit;

    count--;
  }

exit:

  *ppNext = pNext;
  if (OK == status)
    pElement->pNext = (struct MAsn1Element *)pNext;

  return (status);
}

#endif /* (!defined(__DISABLE_MOCANA_ASN1_CREATE_ELEMENT_ARRAY__)) */
