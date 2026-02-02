/**
 * @file   mocctx.c
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

/* Increment or decrement the refCount.
 * <p>If increment is TRUE, increment it, otherwise, decrement it. If the
 * refCount goes to 0, free the MocCtx.
 */
MSTATUS UpdateMocCtxRefCount (
  MocCtx *ppAlgCtx,
  intBoolean increment
  );

extern MSTATUS CreateMocCtx (
  intBoolean isMultiThreaded,
  MocCtx *ppNewMocCtx
  )
{
  MSTATUS status;
  MocContext *pNewCtx = NULL;

  /* Allocate the new shell.
   */
  status = DIGI_CALLOC ((void **)&pNewCtx, sizeof (MocContext), 1);
  if (OK != status)
    goto exit;

  /* Build a mutex.
   */
  if (FALSE != isMultiThreaded)
  {
    status = RTOS_mutexCreate (&(pNewCtx->theMutex), 0, 0);
    if (OK != status)
      goto exit;
  }

  pNewCtx->refCount = 1;
  *ppNewMocCtx = (MocCtx)pNewCtx;
  pNewCtx = NULL;

exit:

  if (NULL != pNewCtx)
  {
    FreeMocCtx ((MocCtx *)&pNewCtx);
  }

  return (status);
}

MOC_EXTERN MSTATUS AcquireMocCtxRef (
  MocCtx pCtx
  )
{
  MocCtx pTemp = pCtx;
  return (UpdateMocCtxRefCount (&pTemp, TRUE));
}

MOC_EXTERN MSTATUS ReleaseMocCtxRef (
  MocCtx pCtx
  )
{
  MocCtx pTemp = pCtx;
  return (UpdateMocCtxRefCount (&pTemp, FALSE));
}

extern MSTATUS FreeMocCtx (
  MocCtx *ppCtx
  )
{
  return (UpdateMocCtxRefCount (ppCtx, FALSE));
}

MSTATUS UpdateMocCtxRefCount (
  MocCtx *ppCtx,
  intBoolean increment
  )
{
  MSTATUS status, fStatus;
  ubyte4 flag;
  MocContext *pCtx = NULL;
  MocSubCtx *pCurrent, *pNext;
  RTOS_MUTEX theMutex = NULL;

  /* Init flag to 0, meaning we don't need to release or free the mutex.
   * If we need to release the mutex, set the 1 bit.
   * If we need to free it, set the 2 bit.
   */
  flag = 0;
  pNext = NULL;

  /* If we're decrementing and there is nothing, we'll do nothing. If
   * incrementing, that's an error.
   */
  status = OK;
  if (FALSE != increment)
    status = ERR_INVALID_ARG;

  if (NULL == ppCtx)
    goto exit;

  if (NULL == *ppCtx)
    goto exit;

  pCtx = (MocContext *)(*ppCtx);
  status = OK;

  /* Acquire the lock so that we can update the refCount with no race conditions.
   * If this fails on decrement, we can recover. But if incrementing, we'll break
   * out a little bit later.
   * Save pCtx->theMutex, because we might be NULLing that field.
   */
  if (NULL != pCtx->theMutex)
  {
    status = RTOS_mutexWait (pCtx->theMutex);
    if (OK == status)
    {
      flag |= 1;
      theMutex = pCtx->theMutex;
    }
  }

  /* If the refCount is already 0, this is unusable.
   * If decrementing, that's fine, don't do anything. But if incrementing, that's
   * an error.
   */
  if (0 >= pCtx->refCount)
    status = ERR_INVALID_ARG;

  /* If we're incrementing and we have an error at this point, return that error.
   * If decrementing, we can still try to do some things.
   */
  if ( (OK != status) && (FALSE != increment) )
    goto exit;

  status = OK;
  if (FALSE == increment)
  {
    pCtx->refCount--;

    /* If this made the refCount go to 0, set the flag to indicate we need to
     * free the mutex. Set theMutex in the Ctx to NULL so no one else can do
     * anything with it.
     * If this made the refCount go negative, then it was 0 already and we're not
     * freeing, we're letting the call that went to 0 do the free.
     */
    if (0 != pCtx->refCount)
      goto exit;

    flag |= 2;
    pNext = pCtx->pSubCtx;
    pCtx->pSubCtx = NULL;
    pCtx->theMutex = NULL;
  }
  else
  {
    pCtx->refCount++;
  }

exit:

  if (0 != (flag & 1))
  {
    fStatus = RTOS_mutexRelease (theMutex);
    if (OK == status)
      status = fStatus;
  }

  /* If the 2 bit is set, we decremented to 0, so destroy everything.
   */
  if (0 != (flag & 2))
  {
    if (NULL != theMutex)
    {
      fStatus = RTOS_mutexFree (&theMutex);
      if (OK == status)
        status = fStatus;
    }

    /* For each SubCtx in the MocCtx, call the FreeFnct.
     */
    while (NULL != pNext)
    {
      pCurrent = pNext;
      pNext = (MocSubCtx *)(pNext->pNext);

      fStatus = pCurrent->FreeFnct ((struct MocSubCtx **)&pCurrent);
      if (OK == status)
        status = fStatus;
    }

    fStatus = DIGI_FREE ((void **)ppCtx);
    if (OK == status)
      status = fStatus;
  }

  return (status);
}

MOC_EXTERN MSTATUS MocAcquireSubCtxRef (
  MocCtx pMocCtx,
  ubyte4 subCtxType,
  MocSubCtx **ppSubCtx
  )
{
  MSTATUS status, fStatus;
  ubyte4 flag;
  MocContext *pCtx = (MocContext *)pMocCtx;
  MocSubCtx *pNext;

  /* flag = 0 means don't release the mutex.
   */
  flag = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == ppSubCtx) )
    goto exit;

  *ppSubCtx = NULL;

  if (NULL != pCtx->theMutex)
  {
    status = RTOS_mutexWait (pCtx->theMutex);
    if (OK != status)
      goto exit;

    flag = 1;
  }

  pNext = pCtx->pSubCtx;

  /* Make sure we have a valid MocCtx.
   */
  status = ERR_INVALID_ARG;
  if (0 >= pCtx->refCount)
    goto exit;

  /* Cycle through the link list, looking for the SubCtx with the given type.
   */
  while (NULL != pNext)
  {
    if (subCtxType == pNext->type)
      break;

    pNext = (MocSubCtx *)(pNext->pNext);
  }

  /* If we went through the entire list without a match, return an error.
   */
  status = ERR_NOT_FOUND;
  if (NULL == pNext)
    goto exit;

  /* pNext is the one we want to return.
   */
  *ppSubCtx = pNext;

  /* Increment the refCount to indicate that we have this reference.
   */
  pCtx->refCount++;
  status = OK;

exit:

  if (0 != flag)
  {
    fStatus = RTOS_mutexRelease (pCtx->theMutex);
    if (OK == status)
      status = fStatus;
  }

  return (status);
}

MOC_EXTERN MSTATUS MocReleaseSubCtxRef (
  MocSubCtx **ppSubCtx
  )
{
  MSTATUS status;
  MocContext *pTemp = NULL;

  /* If there's nothing to release, don't do anything.
   */
  status = OK;
  if (NULL == ppSubCtx)
    goto exit;

  if (NULL == *ppSubCtx)
    goto exit;

  pTemp = (MocContext *)((*ppSubCtx)->pCtxParent);

  /* Just decrement the ref count.
   */
  status = UpdateMocCtxRefCount ((MocCtx *)&pTemp, FALSE);
  if (OK == status)
    *ppSubCtx = NULL;

exit:

  return (status);
}

extern MSTATUS MocLoadNewSubCtx (
  MocCtx pMocCtx,
  MocSubCtx **ppSubCtx
  )
{
  MSTATUS status, fStatus;
  ubyte4 flag;
  MocContext *pCtx = (MocContext *)pMocCtx;
  MocSubCtx *pNext;

  /* Init flag to 0 meaning don't release the mutex. If we do acquire it, we'll
   * reset this flag.
   */
  flag = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == ppSubCtx) )
    goto exit;

  if (NULL == *ppSubCtx)
    goto exit;

  /* If the Ctx has a mutex, acquire it.
   */
  if (NULL != pCtx->theMutex)
  {
    status = RTOS_mutexWait (pCtx->theMutex);
    if (OK != status)
      goto exit;

    flag = 1;
  }

  /* If the refCount indicates this object is not alive, error.
   */
  status = ERR_INVALID_ARG;
  if (0 >= pCtx->refCount)
    goto exit;

  pNext = pCtx->pSubCtx;

  status = OK;
  if (NULL == pCtx->pSubCtx)
  {
    pCtx->pSubCtx = *ppSubCtx;
    goto exit;
  }

  /* Find the end of the link list.
   */
  while (NULL != pNext->pNext)
    pNext = (MocSubCtx *)(pNext->pNext);

  pNext->pNext = (struct MocSubCtx *)(*ppSubCtx);

exit:

  if (OK == status)
  {
    (*ppSubCtx)->pCtxParent = (MocCtx)pCtx;
    *ppSubCtx = NULL;
  }

  if (0 != flag)
  {
    fStatus = RTOS_mutexRelease (pCtx->theMutex);
    if (OK == status)
      status = fStatus;
  }

  return (status);
}
