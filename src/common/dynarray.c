/*
 * dynarray.c
 *
 * Mocana Dynamic Array implementation
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

#include "../common/moptions.h"

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/dynarray.h"

#define DEF_INCREMENT_SIZE  (10)

#if (!defined(__DISABLE_DIGICERT_COMMON_DYNAMIC_ARRAY__))

/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_Init( sbyte4 elementSize, DynArray* pArr)
{
    if ( NULL == pArr)
    {
        return ERR_NULL_POINTER;
    }

    pArr->numUsed = 0;
    pArr->numAllocated = 0;
    pArr->elementSize = elementSize;
    pArr->array = NULL;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_InitEx( sbyte4 elementSize, ubyte4 initialSize, DynArray* pArr)
{
    if ( NULL == pArr)
    {
        return ERR_NULL_POINTER;
    }

    pArr->array = MALLOC( elementSize * initialSize);
    if ( !(pArr->array))
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    pArr->numUsed = 0;
    pArr->numAllocated = initialSize;
    pArr->elementSize = elementSize;
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_Uninit( DynArray* pArr)
{
    if ( NULL== pArr)
    {
        return ERR_NULL_POINTER;
    }

    if ( pArr->array)
    {
        FREE( pArr->array);
        pArr->array = 0;
    }

    return DYNARR_Init( pArr->elementSize, pArr);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_GetElementSize( const DynArray* pArr, sbyte4* pElementSize)
{
    if ((NULL== pArr) || (NULL == pElementSize))
    {
        return ERR_NULL_POINTER;
    }

    *pElementSize = pArr->elementSize;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_GetElementCount( const DynArray* pArr, sbyte4* pElementCount)
{
    if ( NULL== pArr || NULL == pElementCount)
    {
        return ERR_NULL_POINTER;
    }

    *pElementCount = pArr->numUsed;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_Append( DynArray* pArr, const void* pElement)
{
    return DYNARR_AppendEx( pArr, pElement, DEF_INCREMENT_SIZE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_AppendEx( DynArray* pArr, const void* pElement, ubyte4 incrementSize)
{
    void* pDest;

    if (NULL == pArr || NULL == pElement)
    {
        return ERR_NULL_POINTER;
    }

    if ( NULL == pArr->array)
    {
        pArr->array = MALLOC( incrementSize * pArr->elementSize);

        if ( NULL == pArr->array)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        pArr->numAllocated = incrementSize;
    }
    else if (pArr->numAllocated == pArr->numUsed)
    {
        /* reallocate array and copy */
        void* newArr = MALLOC( (pArr->numAllocated + incrementSize) * pArr->elementSize);

        if (NULL == newArr)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        DIGI_MEMCPY( newArr, pArr->array, (pArr->numAllocated * pArr->elementSize));
        FREE( pArr->array);
        pArr->array = newArr;
        pArr->numAllocated += incrementSize;
    }

    pDest = (void*) ( ((ubyte*)pArr->array) + (pArr->numUsed * pArr->elementSize));
    DIGI_MEMCPY( pDest, pElement, pArr->elementSize);
    ++(pArr->numUsed);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_AppendMultiple( DynArray* pArr, const void* pElements, ubyte4 numElems, ubyte4 incrementSize)
{
    void* pDest;
    ubyte4 numBlocks;

    if ( 0 == numElems)
    {
        return OK;
    }
    if (NULL == pArr || NULL == pElements)
    {
        return ERR_NULL_POINTER;
    }

    if ( NULL == pArr->array)
    {
        numBlocks = 1 + (numElems / incrementSize);

        pArr->array = MALLOC( numBlocks * incrementSize * pArr->elementSize);

        if ( NULL == pArr->array)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        pArr->numAllocated = numBlocks * incrementSize;
    }
    else if (pArr->numAllocated <= (sbyte4)(pArr->numUsed + numElems))
    {
        void* newArr;

        numBlocks = 1 + ((pArr->numUsed + numElems) / incrementSize);
        /* reallocate array and copy */
        newArr = MALLOC( numBlocks * incrementSize * pArr->elementSize);

        if (NULL == newArr)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        DIGI_MEMCPY( newArr, pArr->array, (pArr->numAllocated * pArr->elementSize));
        FREE( pArr->array);
        pArr->array = newArr;
        pArr->numAllocated = numBlocks * incrementSize;
    }

    pDest = (void*) ( ((ubyte*)pArr->array) + (pArr->numUsed * pArr->elementSize));
    DIGI_MEMCPY( pDest, pElements, (numElems * pArr->elementSize));
    pArr->numUsed += numElems;
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_Get( const DynArray* pArr, sbyte4 index, void* pElement)
{
    void* pSrc;

    if (NULL == pArr || NULL == pElement)
    {
        return ERR_NULL_POINTER;
    }

    if ( NULL == pArr->array)
    {
        return ERR_INDEX_OOB;
    }

    if ( index < 0 || index >= pArr->numUsed)
    {
        return ERR_INDEX_OOB;
    }

    pSrc = (void*) ( ((ubyte*)pArr->array) + (index * pArr->elementSize));
    DIGI_MEMCPY( pElement, pSrc, pArr->elementSize);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_GetArray( const DynArray* pArr, const void** pArray)
{
    if (NULL == pArr || NULL == pArray)
    {
        return ERR_NULL_POINTER;
    }
    *pArray = pArr->array;
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DYNARR_DetachArray( DynArray* pArr, void** pArray)
{
    if (NULL == pArr || NULL == pArray)
    {
        return ERR_NULL_POINTER;
    }

    *pArray = pArr->array;
    pArr->array = 0;
    return DYNARR_Uninit( pArr);
}

#ifdef __TESTDYNARR__

#define NUMELEMEMTS (331)
int DynArrTests()
{
    DynArray dynArr;
    MSTATUS status;
    sbyte4 elementCount;
    int i, element, retVal = 0;
    long* testArray = 0;

    if  (OK > DYNARR_Init( sizeof(long), &dynArr))
    {
        return 1;
    }

    for (i = 0; i < NUMELEMEMTS; i++)
    {
        if ( OK > DYNARR_Append( &dynArr, &i))
        {
            ++retVal;
        }
    }

    if ( OK > DYNARR_GetElementCount( &dynArr, &elementCount))
    {
        ++retVal;
    }

    if ( NUMELEMEMTS != elementCount)
    {
        ++retVal;
    }

    for (i = 0; i < elementCount; ++i)
    {
        if ( OK > DYNARR_Get( &dynArr, i, &element))
        {
            ++retVal;
        }
        else
        {
            if ( element != i)
            {
                ++retVal;
            }
        }
    }

    if (OK > DYNARR_DetachArray( &dynArr, (void**) &testArray))
    {
        ++retVal;
    }
    else
    {
        for (i = 0; i < NUMELEMEMTS; i++)
        {
            if ( testArray[i] != i)
            {
                ++retVal;
            }
        }
    }

    if ( OK > DYNARR_Uninit( &dynArr))
    {
        ++retVal;
    }

    if (testArray)
    {
        FREE(testArray);
    }

    return retVal;
}


#endif

#endif /* __DISABLE_DIGICERT_COMMON_DYNAMIC_ARRAY__ */
