/*
 * sizedbuffer.c
 *
 * Simple utility to keep track of allocated memory and its size.
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
