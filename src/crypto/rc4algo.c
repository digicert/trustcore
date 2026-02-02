/*
 * rc4algo.c
 *
 * RC4 Algorithm
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (!defined(__DISABLE_ARC4_CIPHERS__) && !defined(__ARC4_HARDWARE_CIPHER__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/rc4algo.h"
#include "../crypto/arc4.h"


/*------------------------------------------------------------------*/

BulkCtx CreateRC4Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
     rc4_key* ctx = (rc4_key*)MALLOC(sizeof(rc4_key));
    MOC_UNUSED(encrypt);

     if (ctx)
     {
         prepare_key( keyMaterial, keyLength, ctx);
     }

     return ctx;
}


/*------------------------------------------------------------------*/

MSTATUS DeleteRC4Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}


/*------------------------------------------------------------------*/

MSTATUS CloneRC4Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    rc4_key *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(rc4_key));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(rc4_key));
    if (OK != status)
        goto exit;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS DoRC4(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength,
              sbyte4 encrypt, ubyte* iv)
{
    MOC_UNUSED(encrypt);
    MOC_UNUSED(iv);

    if (ctx)
    {
        rc4( data, dataLength, ( rc4_key*) ctx);
    }

    return OK;
}

#endif
