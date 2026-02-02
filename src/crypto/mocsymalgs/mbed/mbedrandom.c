/*
 * mbedrandom.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
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
