/*
 * sort.c
 *
 * Byte Sorting Factory
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

    if (OK != (status = DIGI_MALLOC(&pTempItem, itemSize)))
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
            DIGI_MEMCPY(pTempItem, pItemArray + (itemSize * outerIndex), itemSize);

            for (innerIndex = outerIndex; innerIndex >= leftIndex + increment; innerIndex -= increment)
            {
                if (OK > (status = funcComparisonCallback(pTempItem, pItemArray + (itemSize * (innerIndex - increment)), &isLess)))
                    goto exit;

                if (TRUE != isLess)
                    break;

                DIGI_MEMCPY(pItemArray + (itemSize * innerIndex), pItemArray + (itemSize * (innerIndex - increment)), itemSize);
            }

            DIGI_MEMCPY(pItemArray + (itemSize * innerIndex), pTempItem, itemSize);
        }

        increment = increment / 3;
    }
    while (0 < increment);

exit:
    DIGI_FREE(&pTempItem);

    return status;

} /* SORT_shellSort */
