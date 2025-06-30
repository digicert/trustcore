/*
 * sort.c
 *
 * Byte Sorting Factory
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
#include "../common/sort.h"


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
SORT_shellSort(void *pItmArray, ubyte4 itemSize, sbyte4 leftIndex, sbyte4 rightIndex,
               MSTATUS(*funcComparisonCallback)(void *pFirstItem, void *pSecondItem, intBoolean *pRetIsLess))
{
    ubyte*      pItemArray = (ubyte *)pItmArray;
    void*       pTempItem = NULL;
    sbyte4      innerIndex, outerIndex, increment;
    intBoolean  isLess;
    MSTATUS     status;

    if (OK != (status = MOC_MALLOC(&pTempItem, itemSize)))
        goto exit;

    /* find the appropriate increment sequence for the range using Knuth's method */
    /* 1, 4, 13, 40, 121, 364, 1093, 3280, 9841, ... */
    for (increment = 1; increment <= (rightIndex - leftIndex); increment = (increment * 3) + 1)
        ;

    /* sort! */
    do
    {
        for (outerIndex = leftIndex + increment; outerIndex <= rightIndex; outerIndex++)
        {
            MOC_MEMCPY(pTempItem, pItemArray + (itemSize * outerIndex), itemSize);

            for (innerIndex = outerIndex; innerIndex >= leftIndex + increment; innerIndex -= increment)
            {
                if (OK > (status = funcComparisonCallback(pTempItem, pItemArray + (itemSize * (innerIndex - increment)), &isLess)))
                    goto exit;

                if (TRUE != isLess)
                    break;

                MOC_MEMCPY(pItemArray + (itemSize * innerIndex), pItemArray + (itemSize * (innerIndex - increment)), itemSize);
            }

            MOC_MEMCPY(pItemArray + (itemSize * innerIndex), pTempItem, itemSize);
        }

        increment = increment / 3;
    }
    while (0 < increment);

exit:
    MOC_FREE(&pTempItem);

    return status;

} /* SORT_shellSort */
