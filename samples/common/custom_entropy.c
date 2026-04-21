/**
 * @file  custom_entropy.c
 *
 * @brief API definitions for custom entropy injection.
 *
 * @filedoc custom_entropy.h
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
