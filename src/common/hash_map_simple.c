/*
 * hash_map_simple.c
 *
 * Simple Hash Map
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

#include "../common/hash_map_simple.h"
#include "../common/mstdlib.h"

#define HASH_MAP_SIMPLE_MAX_SIZE 65536

#ifdef __ENABLE_HASH_MAP_PRINT__

#include <stdio.h>

#if __LONG_MAX__ == __INT_MAX__
#define PTR_FORMAT "%08x"
#else
#define PTR_FORMAT "%llx"
#endif

MOC_EXTERN void printHashMap(HashMap *pHashMap)
{
    ubyte4 i = 0;

    printf("\n---------------- HASHMAP contents -------------------\n\n");
    for (i = 0; i < pHashMap->size; i++)
    {
        HashMapElement *pElement = &pHashMap->pElements[i];

        while (NULL != pElement)
        {
            if (pElement->pKey)
            {
                printf("Key : " PTR_FORMAT "\n", (usize) (uintptr) pElement->pKey);
                printf("Value : " PTR_FORMAT "\n\n", (usize) (uintptr) pElement->pValue);
            }
            pElement = pElement->pNextElement;
        }
    }
}
#endif /* __ENABLE_HASH_MAP_PRINT__ */


MOC_EXTERN MSTATUS createHashMap(HashMap **ppNewHashMap, ubyte4 size, HashMethod hashMethod)
{
    return createHashMapStaticMem(ppNewHashMap, size, hashMethod, NULL, 0);
}


MOC_EXTERN MSTATUS createHashMapStaticMem(HashMap **ppNewHashMap, ubyte4 size, HashMethod hashMethod, ubyte *pMemBuffer, ubyte4 bufferLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    HashMap *pNewHashMap = NULL;
    memPartDescr *pNewMemPart = NULL;

    if (NULL == ppNewHashMap || NULL == hashMethod)
        goto exit;
    
    status = ERR_HASH_MAP_BAD_SIZE;
    if (!size || size > HASH_MAP_SIMPLE_MAX_SIZE)
        goto exit;
    
    if (NULL != pMemBuffer)
    {
        status = MEM_PART_createPartition(&pNewMemPart, pMemBuffer, bufferLen);
        if (OK != status)
            goto exit;

        status = MEM_PART_alloc(pNewMemPart, sizeof(HashMap), (void **)&pNewHashMap);
        if (OK != status)
            goto exit;

        status = MEM_PART_alloc(pNewMemPart, size * sizeof(HashMapElement), (void **) &pNewHashMap->pElements);
        if (OK != status)
            goto exit;

        status = DIGI_MEMSET((ubyte *) pNewHashMap->pElements, 0x00, size * sizeof(HashMapElement));
        if (OK != status)
            goto exit;

        pNewHashMap->pMemPart = pNewMemPart; pNewMemPart = NULL;
    }
    else
    {
        status = DIGI_MALLOC((void **)&pNewHashMap, sizeof(HashMap));
        if (OK != status)
            goto exit;
        
        status = DIGI_CALLOC((void **)&pNewHashMap->pElements, size, sizeof(HashMapElement));
        if (OK != status)
            goto exit;

        pNewHashMap->pMemPart = NULL;
    }

    pNewHashMap->size = size;
    pNewHashMap->hashMethod = hashMethod;
    
    *ppNewHashMap = pNewHashMap;
    pNewHashMap = NULL;
    
exit:
    
    /* no need to zero out or check return code as status is not OK */
    if (NULL != pNewHashMap)
    {
        if (NULL != pNewHashMap->pElements)
        {   
            /* pNewMemPart did not get transderred until there was success, so can still use it on error */
            if (NULL != pNewMemPart)
            {
                (void) MEM_PART_free(pNewMemPart, (void **) &pNewHashMap->pElements);
            }
            else
            {
                (void) DIGI_FREE((void **)&pNewHashMap->pElements);
            }
        }
        
        if (NULL != pNewMemPart)
        {
            (void) MEM_PART_free(pNewMemPart, (void **) &pNewHashMap);
        }
        else
        {
            (void) DIGI_FREE((void **)&pNewHashMap);
        }
    }

    if (NULL != pNewMemPart)
    {
        (void) MEM_PART_freePartition(&pNewMemPart);
    }
    
    return status;
}


MOC_EXTERN MSTATUS addKey(HashMap *pHashMap, void *pKey, void *pValue)
{
    MSTATUS status = ERR_NULL_POINTER;
    HashMapElement *pElement;
    HashMapElement *pNewElement = NULL;
    ubyte4 hash;
    
    /* we allow pValue to be NULL */
    if (NULL == pHashMap || NULL == pHashMap->hashMethod || NULL == pKey)
        goto exit;
    
    status = ERR_HASH_MAP_INVALID_HASH_OUTPUT;
    hash = pHashMap->hashMethod(pKey);
    if (hash >= pHashMap->size)
        goto exit;
    
    status = OK;
    pElement = &pHashMap->pElements[hash]; /* pElement not NULL by defn */
    
    if (NULL == pElement->pKey)
    {
        pElement->pKey = pKey;
        pElement->pValue = pValue;
        goto exit;
    }
    
    /* see if the key is already there, pointer comparison */
    while ((uintptr) pElement->pKey != (uintptr) pKey && NULL != pElement->pNextElement)
    {
        pElement = pElement->pNextElement;
    }
    
    if ((uintptr) pElement->pKey == (uintptr) pKey) /* key altready in the map, update value */
    {
        pElement->pValue = pValue;
        goto exit;
    }
    
    /* else allocate a new element for the new pKey, pValue pair */
    if (NULL != pHashMap->pMemPart)
    {
        status = MEM_PART_alloc(pHashMap->pMemPart, sizeof(HashMapElement), (void **) &pNewElement);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_MALLOC((void **) &pNewElement, sizeof(HashMapElement));
        if (OK != status)
            goto exit;
    }

    pNewElement->pKey = pKey;
    pNewElement->pValue = pValue;
    pNewElement->pNextElement = NULL;
    
    pElement->pNextElement = pNewElement;
    pNewElement = NULL;
    
exit:
    
    if (NULL != pNewElement)
    {
        DIGI_MEMSET((ubyte *) pNewElement, 0x00, sizeof(HashMapElement));
 
        if (NULL != pHashMap->pMemPart)
        {
            (void) MEM_PART_free(pHashMap->pMemPart, (void **) &pNewElement);
        }
        else
        {
            (void) DIGI_FREE((void **) &pNewElement);
        }
    }
    
    return status;
}

static MSTATUS getOrDeleteKey(HashMap *pHashMap, void *pKey, void **ppRetValue, byteBoolean isDelete)
{
    MSTATUS status = ERR_NULL_POINTER;
    HashMapElement *pTemp = NULL;
    HashMapElement *pElement;
    ubyte4 hash;
    
    if (NULL == pHashMap || NULL == pHashMap->hashMethod || NULL == pKey || NULL == ppRetValue)
        goto exit;
    
    status = ERR_HASH_MAP_INVALID_HASH_OUTPUT;
    hash = pHashMap->hashMethod(pKey);
    if (hash >= pHashMap->size)
        goto exit;
    
    status = OK;
    pElement = &pHashMap->pElements[hash]; /* pElement not NULL by defn */
    
    /* look for the key, pointer comparison, pTemp will store the previous element */
    while ((uintptr) pElement->pKey != (uintptr) pKey && NULL != pElement->pNextElement)
    {
        pTemp = pElement;
        pElement = pElement->pNextElement;
    }
    
    if ((uintptr) pElement->pKey == (uintptr) pKey)
    {
        *ppRetValue = pElement->pValue;
        
        if (isDelete)
        {
            if (NULL == pTemp)  /* ie we are deleting the first element in the list */
            {
                if (NULL == pElement->pNextElement)  /* there are no more elements, just zero out */
                {
                    pElement->pKey = NULL;
                    pElement->pValue = NULL;
                }
                else  /* there are more elements, copy the second to the first and delete the second */
                {
                    /* Now use pTemp to store the next element */
                    pTemp = pElement->pNextElement;
                    
                    pElement->pKey = pTemp->pKey;
                    pElement->pValue = pTemp->pValue;
                    pElement->pNextElement = pTemp->pNextElement;
                    
                    status = DIGI_MEMSET((ubyte *) pTemp, 0x00, sizeof(HashMapElement));
                    if (OK != status)
                        goto exit;
                    
                    if (NULL != pHashMap->pMemPart)
                    {
                        status = MEM_PART_free(pHashMap->pMemPart, (void **) &pTemp);
                    }
                    else
                    {
                        status = DIGI_FREE((void **) &pTemp);
                    }
                }
            }
            else  /* we are deleting in the middle or end of the list */
            {
                pTemp->pNextElement = pElement->pNextElement;
                
                status = DIGI_MEMSET((ubyte *) pElement, 0x00, sizeof(HashMapElement));
                if (OK != status)
                    goto exit;
                
                if (NULL != pHashMap->pMemPart)
                {
                    status = MEM_PART_free(pHashMap->pMemPart, (void **) &pElement);
                }
                else
                {
                    status = DIGI_FREE((void **) &pElement);
                }
            }
        }
    }
    else
    {
        /* set return value to NULL but also set an error status so we know the
         key is not in the map rather than the key's value is just NULL */
        *ppRetValue = NULL;
        status = ERR_HASH_MAP_KEY_NOT_FOUND;
    }
    
exit:
    
    return status;
}


MOC_EXTERN MSTATUS getKey(HashMap *pHashMap, void *pKey, void **ppRetValue)
{
    return getOrDeleteKey(pHashMap, pKey, ppRetValue, FALSE);
}


MOC_EXTERN MSTATUS deleteKey(HashMap *pHashMap, void *pKey, void **ppRetValue)
{
    return getOrDeleteKey(pHashMap, pKey, ppRetValue, TRUE);
}


MOC_EXTERN MSTATUS deleteHashMap(HashMap **ppHashMap)
{
    MSTATUS status = ERR_NULL_POINTER;
    HashMapElement *pElement;
    HashMapElement *pBaseElement;
    memPartDescr *pTemp;
    int i = 0;
    
    if (NULL == ppHashMap || NULL == *ppHashMap || NULL == (*ppHashMap)->pElements)
        goto exit;
    
    for (; i < (*ppHashMap)->size; ++i)
    {
        pBaseElement = &((*ppHashMap)->pElements[i]);
        pElement = pBaseElement->pNextElement;
        
        /* delete any elements after the base element. Move the base elements next ptr in case
         we error midway in the traversal of the linked list */
        while (NULL != pElement)
        {
            pBaseElement->pNextElement = pElement->pNextElement;
            
            status = DIGI_MEMSET((ubyte *) pElement, 0x00, sizeof(HashMapElement));
            if (OK != status)
                goto exit;
            
            if (NULL != (*ppHashMap)->pMemPart)
            {
                status = MEM_PART_free((*ppHashMap)->pMemPart, (void **) &pElement);
                if (OK != status)
                    goto exit;
            }
            else
            {
                status = DIGI_FREE((void **) &pElement);
                if (OK != status)
                    goto exit;
            }

            pElement = pBaseElement->pNextElement;
        }
    }
    
    /* zero and free the array of elements */
    status = DIGI_MEMSET((ubyte *) (*ppHashMap)->pElements, 0x00, (*ppHashMap)->size * sizeof(HashMapElement));
    if (OK != status)
        goto exit;

    if (NULL != (*ppHashMap)->pMemPart)
    {
        status = MEM_PART_free((*ppHashMap)->pMemPart, (void **) &(*ppHashMap)->pElements);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_FREE((void **) &(*ppHashMap)->pElements);
        if (OK != status)
            goto exit;
    }

    /* make a copy of the mem partition if there is one, then zero and free the outer shell */
    pTemp = (*ppHashMap)->pMemPart;

    status = DIGI_MEMSET((ubyte *) *ppHashMap, 0x00, sizeof(HashMap));
    if (OK != status)
        goto exit;
    
    if (NULL != pTemp)
    {
        status = MEM_PART_free(pTemp, (void **) ppHashMap);
        if (OK != status)
            goto exit;

        status = MEM_PART_freePartition(&pTemp);
    }
    else
    {
        status = DIGI_FREE((void **) ppHashMap);
    }

exit:
    
    return status;
}


MOC_EXTERN MSTATUS iterateHashMap(HashMap *pHashMap, ubyte4 *pLastIndex, void **ppLastKey, void **ppLastValue)
{
    MSTATUS status = OK;
    ubyte4 i;
    byteBoolean lastElm = FALSE;

    if (NULL == pLastIndex || NULL == ppLastKey || NULL == ppLastValue)
        return ERR_NULL_POINTER;

    for (i = *pLastIndex; i < pHashMap->size; i++)
    {
        HashMapElement *pElement = &pHashMap->pElements[i];
        HashMapElement *pNextElement = NULL;

        while (NULL != pElement && NULL != pElement->pKey)
        {
            if (NULL == *ppLastKey || lastElm)
            {
                *ppLastKey = pElement->pKey;
                *ppLastValue = pElement->pValue;
                *pLastIndex = i;
                goto exit;
            }

            pNextElement = pElement->pNextElement;
            
            if (*ppLastKey == pElement->pKey)
            {
                if (NULL != pNextElement)
                {
                    *ppLastKey = pNextElement->pKey;
                    *ppLastValue = pNextElement->pValue;
                    *pLastIndex = i;
                    goto exit;
                }
                else
                {
                    lastElm = TRUE;
                }
            }

            pElement = pNextElement;
        }
    }

    status = ERR_NOT_FOUND;

exit:
   
    return status;
}


MOC_EXTERN MSTATUS allocateMemBlock(HashMap *pHashMap, ubyte4 size, void **ppNewPtr)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pHashMap)
        goto exit;

    if (NULL != pHashMap->pMemPart)
    {
        status = MEM_PART_alloc(pHashMap->pMemPart, size, ppNewPtr);
    }
    else
    {
        status = DIGI_MALLOC(ppNewPtr, size);
    }

exit:

    return status;
}


MOC_EXTERN MSTATUS freeMemBlock(HashMap *pHashMap, void **ppPtr)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pHashMap)
        goto exit;

    if (NULL != pHashMap->pMemPart)
    {
        status = MEM_PART_free(pHashMap->pMemPart, ppPtr);
    }
    else
    {
        status = DIGI_FREE(ppPtr);
    }

exit:

    return status;
}
