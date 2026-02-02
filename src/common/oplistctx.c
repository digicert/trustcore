/**
 * @file   oplistctx.c
 * @brief  Routines that manage the MocCtx.
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

#include "../common/initmocana.h"

extern MSTATUS MBuildOpListCtx (
  MSymOperatorAndInfo *pDigestOperators,
  ubyte4 digestOperatorCount,
  MSymOperatorAndInfo *pSymOperators,
  ubyte4 symOperatorCount,
  MKeyOperatorAndInfo *pKeyOperators,
  ubyte4 keyOperatorCount,
  MocSubCtx **ppNewSubCtx
  )
{
  MSTATUS status;
  ubyte4 totalSize, offset, pad, padS, padK, index, dCount, sCount, kCount;
  ubyte4 largestIndex, opCount, symOffset, keyOffset, sIndex, dIndex, kIndex;
  ubyte *pActiveList = NULL;
  ubyte *pBuffer = NULL;
  MocSubCtx *pNewSubCtx;
  MSubCtxOpList *pOpList;

  status = ERR_NULL_POINTER;
  if (NULL == ppNewSubCtx)
    goto exit;

  /* Build the SubCtx for OperatorLists.
   * We need the MocSubCtx, the localCtx which is an MSubCtxOpList, and copies of
   * each of the lists.
   * In creating a single buffer for both structs we need to make sure the second
   * struct and each of the arrays are on appropriate byte boundaries.
   */
  pad = (16 - (sizeof (MocSubCtx) & 15)) & 15;
  dCount = 0;
  sCount = 0;
  kCount = 0;
  padS = 0;
  padK = 0;
  largestIndex = 0;
  symOffset = digestOperatorCount;
  keyOffset = digestOperatorCount + symOperatorCount;
  opCount = digestOperatorCount + symOperatorCount + keyOperatorCount;

  /* Combine the digests and symKey Operators into one list. */
  totalSize = sizeof (MocSubCtx) + sizeof (MSubCtxOpList) + pad;

  /* If there were no operators specified, create a subctx shell */
  if (0 < opCount)
  {
    /* Allocate a list to keep track of which indexes contain active operators */
    status = DIGI_CALLOC((void **)&pActiveList, 1, opCount);
    if (OK != status)
      goto exit;

    /* Process digest operators if any were provided */
    if ( (NULL != pDigestOperators) && (0 != digestOperatorCount) )
    {
      /* Determine the number of active digest operators in the provided list */
      for (index = 0; index < digestOperatorCount; index++)
      {
        if (NULL != pDigestOperators[index].SymOperator)
        {
          /* We determine if the operator is alive by attempting to get the local
          * type. There is no path for an active operator to return
          * ERR_NOT_IMPLEMENTED on this call, so it must be inactive if that
          * status code is returned. */
          status = pDigestOperators[index].SymOperator (
            NULL, NULL, MOC_SYM_OP_GET_LOCAL_TYPE, NULL, NULL);
          if (ERR_NOT_IMPLEMENTED != status)
          {
            dCount++;
            pActiveList[index] = TRUE;
          }
        }
      }
      largestIndex = digestOperatorCount;
    }

    /* Process symmetric operators if any were provided */
    if ( (NULL != pSymOperators) && (0 != symOperatorCount) )
    {
      /* Determine the number of active symmetric operators in the provided list */
      for (index = 0; index < symOperatorCount; index++)
      {
        if (NULL != pSymOperators[index].SymOperator)
        {
          /* We determine if the operator is alive by attempting to get the local
          * type. There is no path for an active operator to return
          * ERR_NOT_IMPLEMENTED on this call, so it must be inactive if that
          * status code is returned. */
          status = pSymOperators[index].SymOperator (
            NULL, NULL, MOC_SYM_OP_GET_LOCAL_TYPE, NULL, NULL);
          if (ERR_NOT_IMPLEMENTED != status)
          {
            sCount++;
            pActiveList[symOffset + index] = TRUE;
          }
        }
      }

      if (symOperatorCount > largestIndex)
      {
        largestIndex = symOperatorCount;
      }
    }

    padS = (16 - (totalSize & 15)) & 15;
    totalSize += ((dCount + sCount) * sizeof (MSymOperatorAndInfo)) + padS;

    /* Process asymmetric operators if any were provided */
    if ( (NULL != pKeyOperators) && (0 != keyOperatorCount) )
    {
      /* Determine the number of active asymmetric operators in the provided list */
      for (index = 0; index < keyOperatorCount; index++)
      {
        if (NULL != pKeyOperators[index].KeyOperator)
        {
          /* We determine if the operator is alive by attempting to get the local
          * type. There is no path for an active operator to return
          * ERR_NOT_IMPLEMENTED on this call, so it must be inactive if that
          * status code is returned. */
          status = pKeyOperators[index].KeyOperator (
            NULL, NULL, MOC_ASYM_OP_GET_LOCAL_TYPE, NULL, NULL, NULL);
          if (ERR_NOT_IMPLEMENTED != status)
          {
            kCount++;
            pActiveList[keyOffset + index] = TRUE;
          }
        }
      }

      if (keyOperatorCount > largestIndex)
      {
        largestIndex = keyOperatorCount;
      }

      padK = (16 - (totalSize & 15)) & 15;
      totalSize += (kCount * sizeof (MKeyOperatorAndInfo)) + padK;
    }
  }

  status = DIGI_CALLOC ((void **)&pBuffer, totalSize, 1);
  if (OK != status)
    goto exit;

  pNewSubCtx = (MocSubCtx *)pBuffer;
  offset = sizeof (MocSubCtx) + pad;
  pOpList = (MSubCtxOpList *)(pBuffer + offset);
  offset += (sizeof (MSubCtxOpList) + padS);
  pNewSubCtx->type = MOC_SUB_CTX_TYPE_OP_LIST;
  pNewSubCtx->pLocalCtx = (void *)pOpList;
  pNewSubCtx->FreeFnct = MSubCtxOpListFree;
  pOpList->totalSize = totalSize;
  if ( (0 != sCount) || (0 != dCount) )
  {
    pOpList->pSymOperators = (MSymOperatorAndInfo *)(pBuffer + offset);
    offset += ((sCount + dCount) * sizeof (MSymOperatorAndInfo));
  }
  offset += padK;
  if (0 != kCount)
  {
    pOpList->pKeyOperators = (MKeyOperatorAndInfo *)(pBuffer + offset);
  }

  /* Loop over the largest found index and copy the operator if it is in the
   * active list. These type specific index counters are used so that the
   * operators are copied into the correct index. For example if the 0th
   * key operator is not active but the 1st is, then we want to copy the
   * 1st index of the provided key operators into the 0th index in our
   * new array. */
  sIndex = 0;
  kIndex = 0;
  dIndex = 0;
  for (index = 0; index < largestIndex; index++)
  {
    if ( (index < digestOperatorCount) &&
         (TRUE == pActiveList[index]) &&
         (NULL != pDigestOperators) )
    {
      pOpList->pSymOperators[dIndex + sCount].SymOperator =
        pDigestOperators[index].SymOperator;
      pOpList->pSymOperators[dIndex + sCount].pOperatorInfo =
        pDigestOperators[index].pOperatorInfo;
      dIndex++;
    }
    if ( (index < symOperatorCount) &&
         (TRUE == pActiveList[symOffset + index]) &&
         (NULL != pSymOperators) )
    {
      pOpList->pSymOperators[sIndex].SymOperator =
        pSymOperators[index].SymOperator;
      pOpList->pSymOperators[sIndex].pOperatorInfo =
        pSymOperators[index].pOperatorInfo;
      sIndex++;
    }
    if ( (index < keyOperatorCount) &&
         (TRUE == pActiveList[keyOffset + index]) &&
         (NULL != pKeyOperators) )
    {
      pOpList->pKeyOperators[kIndex].KeyOperator =
        pKeyOperators[index].KeyOperator;
      pOpList->pKeyOperators[kIndex].pOperatorInfo =
        pKeyOperators[index].pOperatorInfo;
      kIndex++;
    }
  }

  pOpList->digestIndex = sCount;
  pOpList->symOperatorCount = dCount + sCount;
  pOpList->keyOperatorCount = kCount;

  *ppNewSubCtx = pNewSubCtx;
  pBuffer = NULL;

exit:

  if (NULL != pBuffer)
  {
    DIGI_FREE ((void **)&pBuffer);
  }
  if (NULL != pActiveList)
  {
    DIGI_FREE ((void **)&pActiveList);
  }

  return (status);
}

MOC_EXTERN MSTATUS MSubCtxOpListFree (
  struct MocSubCtx **ppMocSubCtx
  )
{
  MSTATUS status;
  MocSubCtx *pCtx;
  MSubCtxOpList *pOpList;

  status = OK;
  if (NULL == ppMocSubCtx)
    goto exit;

  if (NULL == *ppMocSubCtx)
    goto exit;

  pCtx = (MocSubCtx *)(*ppMocSubCtx);
  pOpList = (MSubCtxOpList *)(pCtx->pLocalCtx);

  /* For the OpList, we created a single buffer to hold the LibCtx and OpList.
   */
  status = DIGI_MEMSET_FREE ((ubyte **)ppMocSubCtx, pOpList->totalSize);

exit:

  return (status);
}
