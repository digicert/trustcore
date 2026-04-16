/*
 * mbedrandom.c
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
 *
 */

#include "../../../crypto/mocasym.h"


#if (defined(__ENABLE_DIGICERT_RSA_MBED__) || \
     defined(__ENABLE_DIGICERT_ECC_P256_MBED__))

#include "../../../crypto/mocsymalgs/mbed/mbedrandom.h"

int MocMbedRngFun(
    void *pRandInfo,
    unsigned char *pBuffer,
    size_t byteCount
    )
{
    MSTATUS status;

    MRandomGenInfo *pInfo = pRandInfo;

    status = ERR_NULL_POINTER;
    if ( (NULL == pInfo) || (NULL == pInfo->RngFun) )
        goto exit;

    status = pInfo->RngFun(pInfo->pRngFunArg, (ubyte4) byteCount, pBuffer);

exit:

    return ((int) status);
}

#endif
