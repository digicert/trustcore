/*
 * ansix9_63_kdf.c
 *
 * ANSI X9.63 KDF
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

/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../crypto/crypto.h"
#include "../harness/harness.h"
#include "../crypto/ansix9_63_kdf.h"

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
ANSIX963KDF_generate( MOC_HASH(hwAccelDescr hwAccelCtx)
                        const BulkHashAlgo* pBulkHashAlgo,
                        ubyte* z, ubyte4 zLength,
                        const ubyte* sharedInfo, ubyte4 sharedInfoLen,
                        ubyte4 retLen, ubyte ret[/*retLen*/])
{
    MSTATUS status;
    ubyte* pTempBuf = 0;
    BulkCtx bulkCtx = 0;
    ubyte4 toHashLen, counter;

    if (!pBulkHashAlgo || !z || !ret)
        return ERR_NULL_POINTER;

    if ( sharedInfoLen && !sharedInfo)
        return ERR_NULL_POINTER;

    /* allocate a "CRYPTO" buffer for everything */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, zLength + 4 + sharedInfoLen +
                                        pBulkHashAlgo->digestSize, TRUE, &pTempBuf)))
    {
        goto exit;
    }

    DIGI_MEMCPY( pTempBuf, z, zLength);  /* Z */
    counter = 1; /* counter's initial value MUST be 0x00000001 */
    BIGEND32( pTempBuf + zLength, counter);

    if (sharedInfoLen > 0)  /* sharedInfo */
    {
        DIGI_MEMCPY(pTempBuf + zLength + 4, sharedInfo, sharedInfoLen);
    }

    toHashLen = zLength + 4 + sharedInfoLen;

    pBulkHashAlgo->allocFunc(MOC_HASH(hwAccelCtx) &bulkCtx);

    while (retLen > 0)
    {
        ubyte4 copied;

        pBulkHashAlgo->initFunc( MOC_HASH(hwAccelCtx) bulkCtx);
        pBulkHashAlgo->updateFunc( MOC_HASH(hwAccelCtx) bulkCtx, pTempBuf, toHashLen);
        pBulkHashAlgo->finalFunc( MOC_HASH(hwAccelCtx) bulkCtx, pTempBuf + toHashLen);

        if ( retLen < pBulkHashAlgo->digestSize)
        {
            copied = retLen;
        }
        else
        {
            copied =  pBulkHashAlgo->digestSize;
        }

        DIGI_MEMCPY(ret, pTempBuf + toHashLen, copied);
        retLen -= copied;
        ret += copied;
        ++counter;
        BIGEND32( pTempBuf + zLength, counter);
    }


exit:

    pBulkHashAlgo->freeFunc( MOC_HASH(hwAccelCtx) &bulkCtx);

    CRYPTO_FREE( hwAccelCtx, TRUE, &pTempBuf);

    return status;
}


