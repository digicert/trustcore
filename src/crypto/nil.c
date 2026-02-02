/*
 * nil.c
 *
 * NIL Encipher & Decipher
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/nil.h"


/*------------------------------------------------------------------*/

#ifdef __ENABLE_NIL_CIPHER__

extern BulkCtx
CreateNilCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    static sbyte4 dummy = 0;
    MOC_UNUSED(keyMaterial);
    MOC_UNUSED(keyLength);
    MOC_UNUSED(encrypt);

    return (BulkCtx)(&dummy);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteNilCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;

    *ctx = NULL;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DoNil(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MOC_UNUSED(ctx);
    MOC_UNUSED(data);
    MOC_UNUSED(dataLength);
    MOC_UNUSED(encrypt);
    MOC_UNUSED(iv);

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CloneNil(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MOC_UNUSED(pCtx);
    MOC_UNUSED(ppNewCtx);

    return OK;
}
#endif /* __ENABLE_NIL_CIPHER__ */
