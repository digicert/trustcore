/*
 * sizedbuffer.c
 *
 * Simple utility to keep track of allocated memory and its size.
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


/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/sizedbuffer.h"


/*------------------------------------------------------------------*/

extern MSTATUS
SB_Allocate(SizedBuffer* pBuff, ubyte4 len)
{
    MSTATUS status = OK;

    if (NULL == pBuff)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pBuff->pHeader = pBuff->data = (ubyte*) MALLOC(len);
    if ( pBuff->data )
    {
        pBuff->length = len;
    }
    else
    {
        pBuff->length = 0;
        status = ERR_MEM_ALLOC_FAIL;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
SB_Release(SizedBuffer* pBuff)
{
    if ((pBuff) && (pBuff->pHeader))
    {
        FREE(pBuff->pHeader);
        pBuff->pHeader = 0;
    }
}
