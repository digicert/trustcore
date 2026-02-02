/*
 * mbitmap.c
 *
 * Mocana Bit Map Factory
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
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/mlimits.h"
#include "../common/mbitmap.h"


/*------------------------------------------------------------------*/

extern MSTATUS
MBITMAP_findVacantIndex(bitmapDescr *pBitMapDescr, ubyte4 *pRetIndex)
{
    ubyte4  arrayIndex, bitIndex;
    MSTATUS status = ERR_BITMAP_TABLE_FULL;

    if ((NULL == pBitMapDescr) || (NULL == pRetIndex))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (arrayIndex = 0; arrayIndex < pBitMapDescr->bitmapSize; arrayIndex++)
    {
        ubyte4 tempArrayVal;

        tempArrayVal = pBitMapDescr->pBitmap[arrayIndex];

        if (UBYTE4_MAX != tempArrayVal)
        {
            ubyte4 bitMask = 0x80000000UL;

            for (bitIndex = 0; (0 != bitMask); bitIndex++, bitMask >>= 1)
            {
                /* find vacant bit */
                if (!(bitMask & tempArrayVal))
                {
                    ubyte4  tempIndex;

                    tempIndex = (pBitMapDescr->bitmapLoIndex + (32 * arrayIndex) + bitIndex);

                    if (pBitMapDescr->bitmapHiIndex >= tempIndex)
                    {
                        /* mark bit */
                        pBitMapDescr->pBitmap[arrayIndex] |= bitMask;

                        /* for return */
                        *pRetIndex = tempIndex;
                        status = OK;
                    }

                    bitMask = 0;
                    break;
                }
            }

            break;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MBITMAP_testAndSetIndex(bitmapDescr *pBitMapDescr, ubyte4 theIndex)
{
    MSTATUS status;

    if (NULL == pBitMapDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((pBitMapDescr->bitmapHiIndex >= theIndex) && (pBitMapDescr->bitmapLoIndex <= theIndex))
    {
        sbyte4 arrayIndex, bitIndex;

        arrayIndex = (theIndex - pBitMapDescr->bitmapLoIndex) / 32;
        bitIndex   = (theIndex - pBitMapDescr->bitmapLoIndex) % 32;

        status = ERR_BITMAP_BIT_IS_SET;

        if (!(pBitMapDescr->pBitmap[arrayIndex] & (ubyte4)(0x80000000UL >> bitIndex)))
        {
            /* set the appropriate bit */
            pBitMapDescr->pBitmap[arrayIndex] |= (ubyte4)(0x80000000UL >> bitIndex);
            status = OK;
        }
    }
    else
    {
        status = ERR_BITMAP_BAD_RANGE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MBITMAP_clearIndex(bitmapDescr *pBitMapDescr, ubyte4 theIndex)
{
    MSTATUS status = ERR_BITMAP_BAD_RANGE;

    if (NULL == pBitMapDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((pBitMapDescr->bitmapHiIndex >= theIndex) && (pBitMapDescr->bitmapLoIndex <= theIndex))
    {
        sbyte4 arrayIndex, bitIndex;

        arrayIndex = (theIndex - pBitMapDescr->bitmapLoIndex) / 32;
        bitIndex   = (theIndex - pBitMapDescr->bitmapLoIndex) % 32;

        /* clear the appropriate bit */
        pBitMapDescr->pBitmap[arrayIndex] &= (ubyte4)(~(0x80000000UL >> bitIndex));

        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MBITMAP_isIndexSet(bitmapDescr *pBitMapDescr, ubyte4 theIndex, intBoolean *pIsIndexSet)
{
    MSTATUS status = ERR_BITMAP_BAD_RANGE;

    if ((NULL == pBitMapDescr) || (NULL == pIsIndexSet))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsIndexSet = FALSE;

    if ((pBitMapDescr->bitmapHiIndex >= theIndex) && (pBitMapDescr->bitmapLoIndex <= theIndex))
    {
        sbyte4 arrayIndex, bitIndex;

        arrayIndex = (theIndex - pBitMapDescr->bitmapLoIndex) / 32;
        bitIndex   = (theIndex - pBitMapDescr->bitmapLoIndex) % 32;

        if (pBitMapDescr->pBitmap[arrayIndex] & ((ubyte4)(0x80000000UL >> bitIndex)))
            *pIsIndexSet = TRUE;

        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MBITMAP_createMap(bitmapDescr **ppRetBitMapDescr, ubyte4 loIndex, ubyte4 hiIndex)
{
    bitmapDescr*    pNewBitMapDescr = NULL;
    ubyte4*         pBitmap = NULL;
    ubyte4          index;
    MSTATUS         status = ERR_BITMAP_CREATE_FAIL;

    if (NULL == ppRetBitMapDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (hiIndex <= loIndex)
        goto exit;

    if (NULL == (pNewBitMapDescr = (bitmapDescr*) MALLOC(sizeof(bitmapDescr))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pNewBitMapDescr->bitmapSize    = ((hiIndex - loIndex) + 31) / 32;
    pNewBitMapDescr->bitmapLoIndex = loIndex;
    pNewBitMapDescr->bitmapHiIndex = hiIndex;

    if (NULL == (pBitmap = (ubyte4*) MALLOC(sizeof(ubyte4) * pNewBitMapDescr->bitmapSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* clear out the bitmap */
    for (index = 0; index < pNewBitMapDescr->bitmapSize; index++)
        pBitmap[index] = 0x00;

    /* link everything up, and return */
    pNewBitMapDescr->pBitmap = pBitmap;     pBitmap = NULL;
    *ppRetBitMapDescr = pNewBitMapDescr;    pNewBitMapDescr = NULL;

    status = OK;

exit:
    if (NULL != pNewBitMapDescr)
        FREE(pNewBitMapDescr);

    if (NULL != pBitmap)
        FREE(pBitmap);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MBITMAP_releaseMap(bitmapDescr **ppFreeBitMapDescr)
{
    MSTATUS         status = OK;

    if (NULL == ppFreeBitMapDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == *ppFreeBitMapDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (*ppFreeBitMapDescr)->pBitmap)
    {
        FREE((*ppFreeBitMapDescr)->pBitmap);
        (*ppFreeBitMapDescr)->pBitmap = NULL;
    }

    FREE(*ppFreeBitMapDescr);
    *ppFreeBitMapDescr = NULL;

exit:
    return status;
}
