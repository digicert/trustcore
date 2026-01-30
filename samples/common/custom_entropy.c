/**
 * @file  custom_entropy.c
 *
 * @brief API definitions for custom entropy injection.
 *
 * @filedoc custom_entropy.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_CUSTOM_ENTROPY_INJECT__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"

#include "custom_entropy.h"

extern MSTATUS DIGICERT_CUSTOM_getEntropy(
    ubyte *pBuffer,
    ubyte4 bufferLen
    )
{
    ubyte4 i = 0;

    /* Validate input parameters */
    if (NULL == pBuffer)
    {
        return ERR_NULL_POINTER;
    }

    /* This function can only return MOC_CUSTOM_ENTROPY_LEN bytes of entropy material */
    if (bufferLen > MOC_CUSTOM_ENTROPY_LEN)
    {
        return ERR_BUFFER_OVERFLOW;
    }

    /* Populate with dummy data, note this is not viable entropy for a real world
     * use case. */
    for(i = 0; i < bufferLen; i++)
    {
        pBuffer[i] = i;
    }

    return OK;
}

#endif /* ifdef __ENABLE_DIGICERT_CUSTOM_ENTROPY_INJECT__ */