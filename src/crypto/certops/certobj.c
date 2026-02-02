/*
 * certobj.c
 *
 * Functions for handling the Cert or Request object.
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
#include "../../crypto/certops/certobj.h"

MSTATUS MCreateCertObj (
  ubyte4 type,
  ubyte **ppDer,
  ubyte4 derLen,
  MAsn1Element **ppArray,
  MCertOrRequestObject **ppNewObj,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MCertOrRequestObject *pNew = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppArray) || (NULL == ppDer) || (0 == derLen) ||
       (NULL == ppNewObj) )
    goto exit;

  if ( (NULL == *ppArray) || (NULL == *ppDer) )
    goto exit;

  status = ERR_INVALID_INPUT;
  if ( (MOC_CERT_OBJ_TYPE_CERT != type) &&
       (MOC_CERT_OBJ_TYPE_REQUEST != type) )
    goto exit;

  status = DIGI_MALLOC (
    (void **)&pNew, sizeof (MCertOrRequestObject));
  if (OK != status)
    goto exit;

  pNew->type = type;
  pNew->pDer = *ppDer;
  pNew->derLen = derLen;
  pNew->pArray = *ppArray;
  pNew->pExtArray = NULL;
  pNew->extIndex = 0;
  pNew->pObjMem = NULL;
  *ppNewObj = pNew;

  pNew = NULL;
  *ppArray = NULL;
  *ppDer = NULL;

exit:

  if (NULL != pNew)
  {
    DIGI_FREE ((void **)&pNew);
  }

  return (status);
}

MSTATUS MFreeCertObj (
  MCertOrRequestObject **ppObj,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status, fStatus;
  MObjectMemory *pCurrent, *pNext;

  /* Anything to free?
   */
  status = OK;
  if (NULL == ppObj)
    goto exit;

  if (NULL == *ppObj)
    goto exit;

  pCurrent = (*ppObj)->pObjMem;

  if (NULL != (*ppObj)->pExtArray)
  {
    fStatus = MAsn1FreeElementArray (&((*ppObj)->pExtArray));
    if (OK == status)
      status = fStatus;
  }
  if (NULL != (*ppObj)->pArray)
  {
    fStatus = MAsn1FreeElementArray (&((*ppObj)->pArray));
    if (OK == status)
      status = fStatus;
  }
  if (NULL != (*ppObj)->pDer)
  {
    fStatus = DIGI_FREE ((void **)&((*ppObj)->pDer));
    if (OK == status)
      status = fStatus;
  }
  while (NULL != pCurrent)
  {
    pNext = pCurrent->pNext;
    fStatus = DIGI_MEMSET_FREE (
      (ubyte **)&(pCurrent->pBuffer), pCurrent->bufferSize);
    if (OK == status)
      status = fStatus;

    fStatus = DIGI_MEMSET_FREE (
      (ubyte **)&pCurrent, sizeof (MObjectMemory));
    if (OK == status)
      status = fStatus;

    pCurrent = pNext;
  }

  fStatus = DIGI_FREE ((void **)ppObj);
  if (OK == status)
    status = fStatus;

exit:

  return (status);
}

MSTATUS MLoadMemoryIntoCertObject (
  MCertOrRequestObject *pObj,
  ubyte4 flag,
  void **ppBuffer,
  ubyte4 bufferSize
  )
{
  MSTATUS status;
  MObjectMemory *pNewEntry = NULL;

  /* Create a new shell.
   */
  status = DIGI_MALLOC ((void **)&pNewEntry, sizeof (MObjectMemory));
  if (OK != status)
    goto exit;

  /* Set the fields.
   */
  pNewEntry->flag = flag;
  pNewEntry->pBuffer = *ppBuffer;
  pNewEntry->bufferSize = bufferSize;

  /* Now place it at the front of the list.
   */
  pNewEntry->pNext = (struct MObjectMemory *)(pObj->pObjMem);
  pObj->pObjMem = pNewEntry;
  pNewEntry = NULL;

  *ppBuffer = NULL;

exit:

  if (NULL != pNewEntry)
  {
    DIGI_FREE ((void **)&pNewEntry);
  }

  return (status);
}

MSTATUS MGetMemoryInfoCertObject (
  MCertOrRequestObject *pObj,
  ubyte4 flag,
  void **ppBuffer,
  ubyte4 *pBufferLen
  )
{
  MSTATUS status;
  MObjectMemory *pCurrent, *pNext;

  status = ERR_NULL_POINTER;
  if ( (NULL == pObj) || (NULL == ppBuffer) || (NULL == pBufferLen) )
    goto exit;

  *ppBuffer = NULL;
  *pBufferLen = 0;

  /* An input of 0 for flag will always return no result.
   */
  pCurrent = NULL;
  if (0 != flag)
    pCurrent = pObj->pObjMem;

  /* Search all the entries for a matching flag.
   */
  while (NULL != pCurrent)
  {
    pNext = pCurrent->pNext;
    if (flag == pCurrent->flag)
      break;

    pCurrent = pNext;
  }

  /* If pCurrent is not NULL, that has the result.
   * Otherwise, return ERR_NOT_FOUND.
   */
  status = ERR_NOT_FOUND;
  if (NULL != pCurrent)
  {
    *ppBuffer = pCurrent->pBuffer;
    *pBufferLen = pCurrent->bufferSize;
    status = OK;
  }

exit:

  return (status);
}
